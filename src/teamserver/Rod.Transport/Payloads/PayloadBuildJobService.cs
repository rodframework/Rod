using System.Collections.Concurrent;
using System.Threading.Channels;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Rod.Audit;
using Rod.BuildPipeline.PayloadBuild;
using Rod.CoreState.Operators;

namespace Rod.Transport.Payloads;

/// <summary>
/// Runs payload builds as background jobs (architecture.md Sec 6). A build
/// invokes a real toolchain -- the .NET unit runs a publish -- so it takes the
/// kind of time an HTTP request must not hold open and a browser refresh must
/// not lose. <c>Enqueue</c> accepts a validated <see cref="BuildRequest"/> and
/// returns the job immediately; a single worker drains the queue one build at
/// a time (toolchains want serialization, not contention), and each finished
/// build is stored and audited through <see cref="PayloadBuildRecorder"/> --
/// byte-for-byte the same completion the synchronous build endpoint performs.
///
/// Like the listener registry this is process-local state by design: the
/// durable records of a build are the stored artifact and its audit fact, so
/// an in-flight job lost to a restart is re-requested, not reconstructed.
/// </summary>
public sealed class PayloadBuildJobService : IHostedService
{
    // The build window an operator scrolls back through; older terminal jobs
    // are dropped on enqueue so the registry stays bounded.
    private const int RetainedJobsPerEngagement = 50;

    private readonly Channel<PayloadBuildJob> _pending =
        Channel.CreateUnbounded<PayloadBuildJob>(new UnboundedChannelOptions { SingleReader = true });
    private readonly ConcurrentDictionary<Guid, PayloadBuildJob> _jobs = new();
    private readonly PayloadBuildService _builds;
    private readonly IPayloadStore _payloads;
    private readonly IAuditStore _audit;
    private readonly TimeProvider _clock;
    private readonly ILogger<PayloadBuildJobService> _logger;
    private readonly CancellationTokenSource _stopping = new();
    private Task? _loop;

    public PayloadBuildJobService(
        PayloadBuildService builds,
        IPayloadStore payloads,
        IAuditStore audit,
        TimeProvider clock,
        ILogger<PayloadBuildJobService> logger)
    {
        _builds = builds;
        _payloads = payloads;
        _audit = audit;
        _clock = clock;
        _logger = logger;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        // The boot sweep for work directories earlier builds could not clean
        // (a crash, an OOM kill, a lost host): the per-build cleanup in each
        // finally cannot cover those, and a hermetic target tree is hundreds
        // of megabytes per abandoned build. Best-effort; a locked file is
        // next boot's sweep.
        try
        {
            RustBuildUnit.SweepAbandonedWorkDirectories();
            Rod.BuildPipeline.PayloadBuild.GoBuildUnit.SweepAbandonedWorkDirectories();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "The startup sweep of abandoned build work directories failed.");
        }

        _loop ??= Task.Run(() => RunAsync(_stopping.Token));
        return Task.CompletedTask;
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        _pending.Writer.TryComplete();
        _stopping.Cancel();
        if (_loop is not null)
        {
            try
            {
                await _loop.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
        }
    }

    /// <summary>
    /// Accepts a build request and returns its job in the queued state. The
    /// caller has already validated the request body; the job carries whatever
    /// the build then refuses as its terminal failure.
    /// </summary>
    public PayloadBuildJob Enqueue(BuildRequest request)
    {
        var job = new PayloadBuildJob(request.EngagementId.Value, request.RequestedBy, request, _clock.GetUtcNow());
        _jobs[job.JobId] = job;
        TrimHistory(request.EngagementId.Value);
        _pending.Writer.TryWrite(job);
        return job;
    }

    /// <summary>The engagement's jobs, newest first.</summary>
    public IReadOnlyList<PayloadBuildJob> List(Guid engagementId)
        => _jobs.Values
            .Where(j => j.EngagementId == engagementId)
            .OrderByDescending(j => j.RequestedAt)
            .ToArray();

    /// <summary>The job, or null when unknown or outside the engagement.</summary>
    public PayloadBuildJob? Find(Guid engagementId, Guid jobId)
        => _jobs.TryGetValue(jobId, out var job) && job.EngagementId == engagementId ? job : null;

    private void TrimHistory(Guid engagementId)
    {
        var history = _jobs.Values
            .Where(j => j.EngagementId == engagementId)
            .OrderBy(j => j.RequestedAt)
            .ToArray();
        var excess = history.Length - RetainedJobsPerEngagement;
        for (var i = 0; i < excess; i++)
        {
            // Only terminal jobs are evictable; the queued/running head of the
            // list is the live work and stays regardless.
            if (history[i].IsTerminal)
            {
                _jobs.TryRemove(history[i].JobId, out _);
            }
        }
    }

    private async Task RunAsync(CancellationToken stoppingToken)
    {
        await foreach (var job in _pending.Reader.ReadAllAsync(stoppingToken).ConfigureAwait(false))
        {
            job.MarkRunning(_clock.GetUtcNow());
            try
            {
                var artifact = await _builds.BuildAsync(job.Request, stoppingToken).ConfigureAwait(false);
                var response = await PayloadBuildRecorder.RecordAsync(
                    artifact, job.RequestedBy, _payloads, _audit, stoppingToken).ConfigureAwait(false);
                job.MarkCompleted(response, _clock.GetUtcNow());
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                throw;
            }
            catch (InvalidOperationException ex)
            {
                // No build unit for the requested language (or another
                // contract failure): an operator mistake, surfaced verbatim.
                job.MarkFailed(ex.Message, _clock.GetUtcNow());
            }
            catch (BuildUnitFailureException ex)
            {
                // A toolchain fault, not an operator mistake: the job's error
                // stays generic and the log carries the detail -- the same
                // split the synchronous build endpoint applies.
                _logger.LogError(ex, "Background payload build {JobId} failed.", job.JobId);
                job.MarkFailed("Payload build failed; see the teamserver log.", _clock.GetUtcNow());
            }
            catch (Exception ex)
            {
                // The build unit failed (disk, cancellation of a child
                // process). Keep the job's error generic; the server log
                // carries the detail.
                _logger.LogError(ex, "Background payload build {JobId} failed.", job.JobId);
                job.MarkFailed("Payload build failed; see the teamserver log.", _clock.GetUtcNow());
            }
        }
    }
}

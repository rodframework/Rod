using System.Net;
using System.Net.Http.Json;
using Microsoft.Extensions.DependencyInjection;
using Rod.Transport.Endpoints;
using static Rod.Integration.Tests.EngagementSetup;

namespace Rod.Integration.Tests;

/// <summary>
/// Acceptance: payload builds run as background jobs. A POST returns 202 with
/// the queued job; the build finishes into the payload store and the audit
/// trail on the job worker's schedule; GET lists the engagement's jobs so any
/// view (including a browser refresh) observes progress and retrieves the
/// finished artifact. A request the validator refuses never queues; a build
/// the pipeline cannot satisfy (no unit for the language) fails the job with
/// the reason instead of an error response minutes later.
/// </summary>
public class PayloadJobTests
{
    // The record's positional parameters are required up front; nulls keep a
    // minimal request (server defaults apply).
    private static PayloadEndpoints.BuildPayloadRequest Request(
        string unit = "rod-rust",
        string @class = "Implant",
        string? mode = null,
        string? listenerId = null)
        => new(unit, @class, TargetOs: null, TargetArch: null, ListenerId: listenerId,
            UriPath: null, SleepSeconds: null, JitterSeconds: null, KillDate: null, Mode: mode);

    // Every build names its front: an engagement-scoped https listener is the
    // light default these tests dial.
    private static async Task<string> CreateFrontListenerAsync(HttpClient client, string engagementId)
    {
        var created = await client.PostAsJsonAsync(
            $"/engagements/{engagementId}/listeners",
            new ListenerEndpoints.CreateListenerRequest(
                Name: "job-front", Transport: "tcp",
                BindAddress: $"127.0.0.1:{TestSupport.GetFreeTcpPort()}",
                PublicEndpoint: "10.0.0.5:5443"));
        created.EnsureSuccessStatusCode();
        return (await created.Content.ReadFromJsonAsync<ListenerEndpoints.ListenerResponse>())!.Id;
    }

    [RustFact]
    public async Task BuildJob_CompletesAndTheArtifactDownloads()
    {
        var (client, host, _) = AuthenticatedHost.Create();
        using (client)
        using (host)
        {
            await AuthenticatedHost.LoginAsync(client);
            var engagementId = await CreateEngagementAsync(client);
            var frontId = await CreateFrontListenerAsync(client, engagementId);

            var accepted = await client.PostAsJsonAsync(
                $"/engagements/{engagementId}/payload-jobs", Request(listenerId: frontId));
            Assert.Equal(HttpStatusCode.Accepted, accepted.StatusCode);
            var job = await accepted.Content.ReadFromJsonAsync<PayloadJobEndpoints.PayloadJobResponse>();
            Assert.NotNull(job);
            // The worker may already have picked the job up; either pre-terminal
            // state is the accepted answer.
            Assert.Contains(job!.State, new[] { "queued", "running" });
            Assert.Null(job.Artifact);

            // The whole point of the queue: a real build takes toolchain time.
            job = await WaitForTerminalAsync(client, engagementId, job.JobId, TimeSpan.FromMinutes(5));
            Assert.Equal("completed", job.State);
            Assert.NotNull(job.Artifact);
            Assert.True(job.Artifact!.Size > 0);

            // The finished artifact downloads through the ordinary payload route.
            var download = await client.GetAsync(
                $"/engagements/{engagementId}/payloads/{job.Artifact.ArtifactId}");
            download.EnsureSuccessStatusCode();
            Assert.True((await download.Content.ReadAsByteArrayAsync()).Length > 0);

            // Default contact protection (architecture.md Sec 8/9): the
            // build minted the per-artifact key the artifact seals its
            // contacts under, recorded beside the payload with the baked
            // token -- the pair the enroll-time key bind resolves.
            var payloads = host.Services.GetRequiredService<Rod.Audit.IPayloadStore>();
            var record = await payloads.FindAsync(
                Guid.Parse(job.Artifact.ArtifactId), Guid.Parse(engagementId));
            Assert.NotNull(record);
            Assert.NotNull(record!.EnvelopeKeyId);
            Assert.NotNull(record.EnvelopeKey);
            Assert.NotNull(record.TokenId);

            // The job list -- the view a refreshed browser reloads -- carries the
            // completed job.
            var jobs = await client.GetFromJsonAsync<PayloadJobEndpoints.PayloadJobResponse[]>(
                $"/engagements/{engagementId}/payload-jobs");
            Assert.NotNull(jobs);
            Assert.Contains(jobs!, j => j.JobId == job.JobId && j.State == "completed");
        }
    }

    [Fact]
    public async Task BuildJob_MalformedBody_IsRefusedWithoutQueuing()
    {
        var (client, _, _) = AuthenticatedHost.Create();
        await AuthenticatedHost.LoginAsync(client);
        var engagementId = await CreateEngagementAsync(client);
        var frontId = await CreateFrontListenerAsync(client, engagementId);

        var refused = await client.PostAsJsonAsync(
            $"/engagements/{engagementId}/payload-jobs",
            Request(listenerId: frontId, mode: "sometimes"));
        Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);

        var jobs = await client.GetFromJsonAsync<PayloadJobEndpoints.PayloadJobResponse[]>(
            $"/engagements/{engagementId}/payload-jobs");
        Assert.NotNull(jobs);
        Assert.Empty(jobs!);
    }

    [Fact]
    public async Task BuildJob_SocketFront_IsAccepted()
    {
        // The socket family is self-sufficient: a stream-mode build holds
        // the live session on the same connection enrollment's opening
        // exchange rode -- the contact always rides the front. A Go
        // language request keeps the worker from invoking the toolchain;
        // the parser's acceptance is what this pins.
        var (client, _, _) = AuthenticatedHost.Create();
        await AuthenticatedHost.LoginAsync(client);
        var engagementId = await CreateEngagementAsync(client);
        var front = await client.PostAsJsonAsync(
            $"/engagements/{engagementId}/listeners",
            new ListenerEndpoints.CreateListenerRequest(
                Name: "socket-front", Transport: "tcp",
                BindAddress: $"127.0.0.1:{TestSupport.GetFreeTcpPort()}",
                PublicEndpoint: "10.0.0.5:5090"));
        front.EnsureSuccessStatusCode();
        var frontId = (await front.Content.ReadFromJsonAsync<ListenerEndpoints.ListenerResponse>())!.Id;

        var accepted = await client.PostAsJsonAsync(
            $"/engagements/{engagementId}/payload-jobs",
            Request(unit: "rod-go", listenerId: frontId));
        Assert.Equal(HttpStatusCode.Accepted, accepted.StatusCode);
        var job = await accepted.Content.ReadFromJsonAsync<PayloadJobEndpoints.PayloadJobResponse>();
        Assert.NotNull(job);
    }

    [Fact]
    public async Task BuildJob_NoUnitForLanguage_FailsTheJobWithTheReason()
    {
        var (client, _, _) = AuthenticatedHost.Create();
        await AuthenticatedHost.LoginAsync(client);
        var engagementId = await CreateEngagementAsync(client);
        var frontId = await CreateFrontListenerAsync(client, engagementId);

        var accepted = await client.PostAsJsonAsync(
            $"/engagements/{engagementId}/payload-jobs",
            // Nim is the still-empty community slot; Go carries its in-tree
            // reference unit now, so it would build.
            Request(unit: "community-nim", listenerId: frontId));
        Assert.Equal(HttpStatusCode.Accepted, accepted.StatusCode);
        var job = await accepted.Content.ReadFromJsonAsync<PayloadJobEndpoints.PayloadJobResponse>();
        Assert.NotNull(job);

        job = await WaitForTerminalAsync(client, engagementId, job!.JobId, TimeSpan.FromSeconds(30));
        Assert.Equal("failed", job.State);
        Assert.Contains("No build unit", job.Error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task BuildJob_UnknownEngagementOrJob_IsNotFound()
    {
        var (client, _, _) = AuthenticatedHost.Create();
        await AuthenticatedHost.LoginAsync(client);

        var accepted = await client.PostAsJsonAsync(
            $"/engagements/{Guid.NewGuid()}/payload-jobs",
            Request());
        Assert.Equal(HttpStatusCode.NotFound, accepted.StatusCode);

        var engagementId = await CreateEngagementAsync(client);
        var missing = await client.GetAsync(
            $"/engagements/{engagementId}/payload-jobs/{Guid.NewGuid()}");
        Assert.Equal(HttpStatusCode.NotFound, missing.StatusCode);
    }

    private static async Task<PayloadJobEndpoints.PayloadJobResponse> WaitForTerminalAsync(
        HttpClient client,
        string engagementId,
        string jobId,
        TimeSpan timeout)
    {
        var deadline = DateTimeOffset.UtcNow + timeout;
        while (DateTimeOffset.UtcNow < deadline)
        {
            var job = await client.GetFromJsonAsync<PayloadJobEndpoints.PayloadJobResponse>(
                $"/engagements/{engagementId}/payload-jobs/{jobId}");
            Assert.NotNull(job);
            if (job!.State is "completed" or "failed")
                return job;
            await Task.Delay(250);
        }

        throw new Xunit.Sdk.XunitException(
            $"Payload job {jobId} did not reach a terminal state within {timeout}.");
    }
}

using Rod.CoreState.Assets;

namespace Rod.Transport.Campaigns;

/// <summary>
/// The campaign template asset's file shape (architecture.md Sec 11.5,
/// Sec 15.1): the first line is <c>Subject: &lt;text&gt;</c>, one blank line
/// follows, and the rest is the body. The declared path's extension selects
/// plain text against HTML. This is the module ecosystem's content contract
/// the way the hook template's placeholder is: the file format lives with
/// the modules, the parsing rule is stated once here, and the merge grammar
/// itself (<c>{{link}}</c> and friends, <see cref="Rod.CoreState.Campaigns.CampaignLimits"/>)
/// stays the kernel's rendering contract either way.
/// </summary>
public static class CampaignTemplateAsset
{
    /// <summary>
    /// Parses one template asset. Null when the bytes are not the file
    /// shape (no subject line, no separator); the caller turns that into
    /// its refusal naming the asset.
    /// </summary>
    public static (string Subject, string Body, bool BodyIsHtml)? Parse(ModuleAsset asset)
    {
        var text = System.Text.Encoding.UTF8.GetString(asset.Content).Replace("\r\n", "\n");
        var firstNewline = text.IndexOf('\n');
        if (firstNewline <= 0)
            return null;

        var subjectLine = text[..firstNewline].TrimEnd();
        if (!subjectLine.StartsWith("Subject:", StringComparison.OrdinalIgnoreCase)
            || subjectLine.Length <= "Subject:".Length)
            return null;

        // The blank separator line: without it there is no body to merge.
        var afterSubject = firstNewline + 1;
        if (afterSubject >= text.Length || text[afterSubject] != '\n')
            return null;

        var subject = subjectLine["Subject:".Length..].Trim();
        var body = text[(afterSubject + 1)..].TrimEnd();
        if (subject.Length == 0 || body.Length == 0)
            return null;

        var extension = Path.GetExtension(asset.Path).ToLowerInvariant();
        return (subject, body, extension is ".html" or ".htm");
    }
}

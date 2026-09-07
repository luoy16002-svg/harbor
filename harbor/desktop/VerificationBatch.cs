using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Harbor;

internal enum VerificationOutcome { Success, Failure, Skipped }
internal sealed record VerificationProgress(int Total, int Completed, int Successful, int Failed, int Skipped);

internal static class VerificationBatch
{
    // Workers retain the caller's synchronization context, allowing desktop callbacks
    // to update the UI without queued progress arriving after the run has ended.
    internal static async Task<VerificationProgress> RunAsync(IReadOnlyList<string> names,
        Func<string, CancellationToken, Task<VerificationOutcome>> verify,
        Action<VerificationProgress> progress, CancellationToken cancellationToken)
    {
        string[] queue = names.Distinct(StringComparer.Ordinal).ToArray();
        if (queue.Length > 512) throw new ArgumentException("A verification batch is limited to 512 proxies.", nameof(names));
        int next = -1;
        object gate = new();
        var state = new VerificationProgress(queue.Length, 0, 0, 0, 0);
        progress(state);
        async Task Worker()
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                int index = Interlocked.Increment(ref next);
                if (index >= queue.Length) return;
                VerificationOutcome outcome;
                try { outcome = await verify(queue[index], cancellationToken); }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { return; }
                if (cancellationToken.IsCancellationRequested) return;
                lock (gate)
                {
                    state = state with
                    {
                        Completed = state.Completed + 1,
                        Successful = state.Successful + (outcome == VerificationOutcome.Success ? 1 : 0),
                        Failed = state.Failed + (outcome == VerificationOutcome.Failure ? 1 : 0),
                        Skipped = state.Skipped + (outcome == VerificationOutcome.Skipped ? 1 : 0)
                    };
                    progress(state);
                }
            }
        }
        await Task.WhenAll(Enumerable.Range(0, Math.Min(2, queue.Length)).Select(_ => Worker()));
        return state;
    }
}

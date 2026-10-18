package inspect

import "time"

// killWaitDelay is the value that configureProcessGroup puts in
// cmd.WaitDelay. After the context is done and the kill is sent, Wait waits
// at most this long for the I/O of the child to finish. Then it closes the
// pipes and returns.
//
// This bounds Wait itself, also when a process that left the group still holds
// stdout open. It does not bound a read on a pipe from cmd.StdoutPipe that the
// caller does before Wait: that read returns only when every writer closes the
// pipe. So the caller must close its end of such a pipe when the context is
// done (see the Inspector contract).
const killWaitDelay = 2 * time.Second

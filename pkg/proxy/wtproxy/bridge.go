package wtproxy

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/webtransport-go"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const copyBufferSize = 32 * 1024

var bufferPool = sync.Pool{
	New: func() any {
		b := make([]byte, copyBufferSize)
		return &b
	},
}

// readerOnly and writerOnly hide the io.WriterTo and io.ReaderFrom fast paths, which would bypass the pooled buffer.
type readerOnly struct{ io.Reader }

type writerOnly struct{ io.Writer }

type canceler interface {
	CancelRead(webtransport.StreamErrorCode)
}

type writeCanceler interface {
	CancelWrite(webtransport.StreamErrorCode)
}

// bridge relays streams, datagrams and the termination of two WebTransport sessions in both directions.
type bridge struct {
	client  *webtransport.Session
	backend *webtransport.Session
	logger  zerolog.Logger

	closeCh chan sessionClose
}

// run blocks until one of the sessions terminates, and then terminates the other one with the same error.
func (b *bridge) run() {
	b.closeCh = make(chan sessionClose, 4)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup

	for _, dir := range []struct{ src, dst *webtransport.Session }{
		{b.client, b.backend},
		{b.backend, b.client},
	} {
		wg.Go(func() { b.acceptStreams(ctx, dir.src, dir.dst) })
		wg.Go(func() { b.acceptUniStreams(ctx, dir.src, dir.dst) })
		wg.Go(func() { b.relayDatagrams(ctx, dir.src, dir.dst) })
	}

	select {
	case <-b.client.Context().Done():
		b.propagateClose(b.client, b.backend)
	case <-b.backend.Context().Done():
		b.propagateClose(b.backend, b.client)
	}

	cancel()
	wg.Wait()
}

// closeGracePeriod is the time given to the stream acceptors to report the error that terminated a session.
// The session context is canceled before the acceptors observe the error, and it does not carry it.
const closeGracePeriod = 200 * time.Millisecond

type sessionClose struct {
	src *webtransport.Session
	err *webtransport.SessionError
}

// reportClose records the error with which the peer terminated the src session.
func (b *bridge) reportClose(src *webtransport.Session, err error) {
	if sessErr, ok := errors.AsType[*webtransport.SessionError](err); ok && sessErr.Remote {
		select {
		case b.closeCh <- sessionClose{src: src, err: sessErr}:
		default:
		}
	}
}

// propagateClose terminates dst with the error code and message that terminated src.
func (b *bridge) propagateClose(src, dst *webtransport.Session) {
	var code webtransport.SessionErrorCode
	var msg string

	timer := time.NewTimer(closeGracePeriod)
	defer timer.Stop()

loop:
	for {
		select {
		case ev := <-b.closeCh:
			if ev.src == src {
				code, msg = ev.err.ErrorCode, ev.err.Message
				break loop
			}
		case <-timer.C:
			break loop
		}
	}

	_ = dst.CloseWithError(code, msg)
}

func (b *bridge) acceptStreams(ctx context.Context, src, dst *webtransport.Session) {
	for {
		in, err := src.AcceptStream(ctx)
		if err != nil {
			b.reportClose(src, err)
			return
		}

		go func() {
			out, err := dst.OpenStreamSync(ctx)
			if err != nil {
				in.CancelRead(0)
				in.CancelWrite(0)
				return
			}

			var wg sync.WaitGroup
			wg.Go(func() { relay(out, in, in, out) })
			wg.Go(func() { relay(in, out, out, in) })
			wg.Wait()
		}()
	}
}

func (b *bridge) acceptUniStreams(ctx context.Context, src, dst *webtransport.Session) {
	for {
		in, err := src.AcceptUniStream(ctx)
		if err != nil {
			b.reportClose(src, err)
			return
		}

		go func() {
			out, err := dst.OpenUniStreamSync(ctx)
			if err != nil {
				in.CancelRead(0)
				return
			}

			relay(out, in, in, out)
		}()
	}
}

func (b *bridge) relayDatagrams(ctx context.Context, src, dst *webtransport.Session) {
	for {
		data, err := src.ReceiveDatagram(ctx)
		if err != nil {
			return
		}

		// Datagrams are unreliable by contract, so the ones that cannot be forwarded are dropped.
		if err := dst.SendDatagram(data); err != nil {
			if _, ok := errors.AsType[*quic.DatagramTooLargeError](err); !ok && ctx.Err() == nil {
				b.logger.Debug().Err(err).Msg("Unable to forward WebTransport datagram")
			}
		}
	}
}

// relay copies data from src to dst, forwarding the termination (graceful or not) of the stream half.
// rd is the receiving half of src, and wr the sending half of dst, they are used to propagate the errors upstream.
func relay(dst io.Writer, src io.Reader, rd canceler, wr writeCanceler) {
	buf := bufferPool.Get().(*[]byte)
	defer bufferPool.Put(buf)

	_, err := io.CopyBuffer(writerOnly{dst}, readerOnly{src}, *buf)
	if err == nil {
		if closer, ok := dst.(io.Closer); ok {
			_ = closer.Close()
		}
		return
	}

	if streamErr, ok := errors.AsType[*webtransport.StreamError](err); ok {
		// The peer reset its sending side (read failed), or asked to stop receiving (write failed).
		// Whichever failed, the other half is aborted with the same code.
		wr.CancelWrite(streamErr.ErrorCode)
		rd.CancelRead(streamErr.ErrorCode)
		return
	}

	if _, ok := errors.AsType[*webtransport.SessionError](err); !ok {
		log.Debug().Err(err).Msg("WebTransport stream relay failed")
	}
	wr.CancelWrite(0)
	rd.CancelRead(0)
}

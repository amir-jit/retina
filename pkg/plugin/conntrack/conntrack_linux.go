// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// package conntrack implements a conntrack plugin for Retina.
package conntrack

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/microsoft/retina/internal/ktime"
	"github.com/microsoft/retina/pkg/log"
	plugincommon "github.com/microsoft/retina/pkg/plugin/common"
	"go.uber.org/zap"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@master -cc clang-14 -cflags "-g -O2 -Wall -D__TARGET_ARCH_${GOARCH} -Wall" -target ${GOARCH} -type conn_key conntrack ./_cprog/conntrack.c -- -I../lib/_${GOARCH} -I../lib/common/libbpf/_src

var (
	ct   *Conntrack
	once sync.Once
)

type Conntrack struct {
	l     *log.ZapLogger
	objs  *conntrackObjects
	ctmap *ebpf.Map
}

func Init() (*Conntrack, error) {
	once.Do(func() {
		ct = &Conntrack{}
	})
	if ct.l == nil {
		ct.l = log.Logger().Named("conntrack")
	}
	if ct.objs != nil {
		return ct, nil
	}

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		ct.l.Error("RemoveMemlock failed", zap.Error(err))
		return ct, err
	}

	objs := &conntrackObjects{}
	err := loadConntrackObjects(objs, &ebpf.CollectionOptions{ //nolint:typecheck
		Maps: ebpf.MapOptions{
			PinPath: plugincommon.ConntrackMapPath,
		},
	})
	if err != nil {
		ct.l.Error("loadConntrackObjects failed", zap.Error(err))
		return ct, err
	}

	ct.objs = objs

	// Get the conntrack map from the objects
	ct.ctmap = objs.conntrackMaps.RetinaConntrackMap

	return ct, nil
}

// Close cleans up the Conntrack plugin.
func (ct *Conntrack) Close() {
	if ct.objs != nil {
		ct.objs.Close()
	}
}

func (ct *Conntrack) gc(timeout time.Duration) {
	var key, nextKey conntrackConnKey
	var value conntrackConnValue

	ct.l.Info("Running Conntrack GC", zap.Duration("timeout", timeout))

	for {
		// Get the next key
		err := ct.ctmap.NextKey(&key, &nextKey)
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			break
		}

		// Get the value for the current key
		err = ct.ctmap.Lookup(&key, &value)
		if err != nil {
			ct.l.Error("Lookup failed", zap.Error(err))
			continue
		}

		// If the last seen time is older than the timeout, delete the key
		// Convert the timestamp from nanoseconds to a time.Time value
		lastSeen := ktime.MonotonicOffset.Nanoseconds() + int64(value.Timestamp)
		if time.Since(time.Unix(0, lastSeen)) > timeout {
			err = ct.ctmap.Delete(&key)
			if err != nil {
				ct.l.Error("Delete failed", zap.Error(err))
			}
		}

		// Log each field of the conntrack entry key and value
		ct.l.Info("ct_key", zap.Uint32("src_ip", key.SrcIp), zap.Uint32("dst_ip", key.DstIp), zap.Uint16("src_port", key.SrcPort), zap.Uint16("dst_port", key.DstPort), zap.Uint8("proto", key.Protocol))
		ct.l.Info("ct_value", zap.Time("last_seen", time.Unix(0, lastSeen)), zap.Uint32("flags", value.Flags))

		// Move on to the next key
		key = nextKey
	}
}

// Start starts the Conntrack GC loop. It runs every 30 seconds and deletes entries older than 5 minutes.
func (ct *Conntrack) Run(ctx context.Context) error {
	ticker := time.NewTicker(30 * time.Second) //nolint:gomnd // 30 seconds
	defer ticker.Stop()

	ct.l.Info("Starting Conntrack GC loop")

	for {
		select {
		case <-ctx.Done():
			ct.Close()
			return nil
		case <-ticker.C:
			ct.gc(5 * time.Minute) //nolint:gomnd // 5 minutes
		}
	}
}

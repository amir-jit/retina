package conntrack

import "github.com/cilium/ebpf"

type IEbpfMap interface {
	BatchUpdate(keys, values interface{}, opts *ebpf.BatchOptions) (int, error)
	BatchDelete(keys interface{}, opts *ebpf.BatchOptions) (int, error)
	Put(key, value interface{}) error
	Delete(key interface{}) error
	Close() error
}

var loadProg = new NativeFunction(Module.findExportByName("libbpf_android.so", "_ZN7android3bpf8loadProgEPKc"), 'int', ['pointer']);
loadProg(Memory.allocUtf8String("/system/etc/bpf/netd.o"))
loadProg(Memory.allocUtf8String("/data/local/tmp/bpf/example.o"))

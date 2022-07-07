var loadProg = new NativeFunction(Module.findExportByName("libbpf_android.so", "_ZN7android3bpf8loadProgEPKcPbS2_"), 'int', ['pointer', 'pointer']);
var critical = Memory.alloc(4)
critical.writeInt(1)
loadProg(Memory.allocUtf8String("/data/local/tmp/bpf/example.o"), critical)

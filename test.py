import debugger

debugger = debugger.debugger()

pid = raw_input("PID : ")

debugger.attach(int(pid))

lists = debugger.enumerate_threads()

for thread in lists:

    thread_context = debugger.get_thread_context(thread)

    print "[*] Dumping registers for thread ID: 0x%08x" % thread
    print "[**] EIP: 0x%08x" % thread_context.Eip
    print "[**] ESP: 0x%08x" % thread_context.Esp
    print "[**] EBP: 0x%08x" % thread_context.Ebp
    print "[**] EAX: 0x%08x" % thread_context.Eax
    print "[**] EBX: 0x%08x" % thread_context.Ebx
    print "[**] ECX: 0x%08x" % thread_context.Ecx
    print "[**] EDX: 0x%08x" % thread_context.Edx
    print "[*] END DUMP"
  
debugger.detach()

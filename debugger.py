# -*- coding: cp949 -*-
from ctypes import *
from define import *

import sys
import time
kernel32 = windll.kernel32

class debugger():

    def __init__(self):
        self.h_process       =     None
        self.pid             =     None
        self.debugger_active =     False
        
    def load(self,path_to_exe):
        
        # dwCreation 플래그를 이용해서 프로세스를 어떻게 생성할 것인지 판단한다.
        # 계산기의 GUI를 보고자 한다면 creation_flags를
        # CREATE_NEW_CONSOLE로 설정하면 된다.
        creation_flags = DEBUG_PROCESS
    
        # 구조체 인스턴스화
        startupinfo         = STARTUPINFO()
        process_information = PROCESS_INFORMATION()

        # 다음 두 옵션은 프로세스가 독립적인 창으로 실행되게 만들어준다.
        # 이는 STARTUPINFO struct 구조체의 설정 내용에 따라 디버기 피로세스에
        # 어떤 영향을 주는지 보여준다.
        startupinfo.dwFlags     = 0x1
        startupinfo.wShoWindow  = 0x0

        #다음에는 STARTUPINFO struct 구조체를 자신의 크기를 나타내는 cb 변수 값을 초기화
        startupinfo.cb = sizeof(startupinfo)

        if kernel32.CreateProcessA(path_to_exe,
                                   None,
                                   None,
                                   None,
                                   None,
                                   creation_flags,
                                   None,
                                   None,
                                   byref(startupinfo),
                                   byref(process_information)):
            
            print "[*] We have successfully launched the process!"
            print "[*] The Process ID I have is: %d" % \
                         process_information.dwProcessId
            self.pid = process_information.dwProcessId
            self.h_process = self.open_process(self,process_information.dwProcessId)
            self.debugger_active = True
        else:    
            print "[*] Error with error code %d." % kernel32.GetLastError()

    def open_process(self,pid):
        
        # PROCESS_ALL_ACCESS = 0x0x001F0FFF
        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS,False,pid) 
        
        return h_process
    
    def attach(self,pid):
        
        self.h_process = self.open_process(pid)
        
        # We attempt to attach to the process
        # if this fails we exit the call
        if kernel32.DebugActiveProcess(pid):
            self.debugger_active = True
            self.pid             = int(pid)
                                  
        else:
            print "[*] Unable to attach to the process."
            
    def run(self):
        
        # Now we have to poll the debuggee for 
        # debugging events           
        while self.debugger_active == True:
            self.get_debug_event() 
    
    def get_debug_event(self):
        
        debug_event    = DEBUG_EVENT()
        continue_status = DBG_CONTINUE
        
        if kernel32.WaitForDebugEvent(byref(debug_event),100):
                
            kernel32.ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, continue_status)

            
    def detach(self):
        
        if kernel32.DebugActiveProcessStop(self.pid):
            print "[*] Finished debugging. Exiting..."
            return True
        else:
            print "There was an error"
            return False
    
    def open_thread (self, thread_id):
        
        h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS, None, thread_id)
        
        if h_thread is not None:
            return h_thread
        else:
            print "[*] Could not obtain a valid thread handle."
            return False
        
    def enumerate_threads(self):
              
        thread_entry     = THREADENTRY32()
        thread_list      = []
        snapshot         = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, self.pid)
        
        if snapshot is not None:
        
            thread_entry.dwSize = sizeof(thread_entry)

            success = kernel32.Thread32First(snapshot, byref(thread_entry))

            while success:
                if thread_entry.th32OwnerProcessID == self.pid:
                    thread_list.append(thread_entry.th32ThreadID)
    
                success = kernel32.Thread32Next(snapshot, byref(thread_entry))
            

            kernel32.CloseHandle(snapshot)
            return thread_list
        else:
            return False
        
    def get_thread_context (self, thread_id):
        
        context = CONTEXT()
        context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS
        
        h_thread = self.open_thread(thread_id)
                        
        if kernel32.GetThreadContext(h_thread, byref(context)):
            kernel32.CloseHandle(h_thread)
            return context 
        else:
            return False
    


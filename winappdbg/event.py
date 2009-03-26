# Copyright (c) 2009, Mario Vilas
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     * Redistributions of source code must retain the above copyright notice,
#       this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice,this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the copyright holder nor the names of its
#       contributors may be used to endorse or promote products derived from
#       this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

# $Id$

"""
Event handling library.

@see: U{http://apps.sourceforge.net/trac/winappdbg/wiki/wiki/Debugging}

@group Event objects:
    Event,
    CreateProcessEvent,
    CreateThreadEvent,
    ExitProcessEvent,
    ExitThreadEvent,
    LoadDLLEvent,
    UnloadDLLEvent,
    OutputDebugStringEvent,
    RIPEvent,
    ExceptionEvent
"""

__all__ = [ 'EventFactory', 'EventHandler' ]

import win32
from breakpoint import ApiHook
from system import ProcessHandle, ThreadHandle, FileHandle
from system import Module, Thread, Process

import ctypes

#==============================================================================

class Event (object):
    """
    Event object.
    
    @type eventName: str
    @cvar eventName: User-friendly name of the event.
    
    @type debug: L{Debug}
    @ivar debug: Debug object that received the event.
    
    @type raw: L{DEBUG_EVENT}
    @ivar raw: Raw DEBUG_EVENT structure as used by the Win32 API.
    
    @type continueStatus: int
    @ivar continueStatus: Continue status to pass to L{win32.ContinueDebugEvent}.
    """

    eventName = 'Unknown event'

    def __init__(self, debug, raw):
        """
        @type  debug: L{Debug}
        @param debug: Debug object that received the event.
        
        @type  raw: L{DEBUG_EVENT}
        @param raw: Raw DEBUG_EVENT structure as used by the Win32 API.
        """
        self.debug          = debug
        self.raw            = raw
        self.continueStatus = win32.DBG_EXCEPTION_NOT_HANDLED

    def get_event_name(self):
        """
        @rtype:  str
        @return: User-friendly name of the event.
        """
        return self.eventName

    def get_code(self):
        """
        @rtype:  int
        @return: Debug event code as defined in the Win32 API.
        """
        return self.raw.dwDebugEventCode

    def get_pid(self):
        """
        @see: L{get_process}

        @rtype:  int
        @return: Process global ID where the event occured.
        """
        return self.raw.dwProcessId

    def get_tid(self):
        """
        @see: L{get_thread}

        @rtype:  int
        @return: Thread global ID where the event occured.
        """
        return self.raw.dwThreadId

    def get_process(self):
        """
        @see: L{get_pid}

        @rtype:  L{Process}
        @return: Process where the event occured.
        """
        # We can't assume the Process object will be in the System snapshot.
        # The user may have cleared the snapshot, or some debug events could
        # have been missed (it seems to happen sometimes when automatically
        # following processes created by the debuguee, and I could swear the
        # bug is not in my code but in the Win32 API).
        pid     = self.get_pid()
        system  = self.debug.system
        if system.has_process(pid):
            process = system.get_process(pid)
        else:
            process = Process(pid)
            system._ProcessContainer__add_process(process)
        return process

    def get_thread(self):
        """
        @see: L{get_tid}
        
        @rtype:  L{Thread}
        @return: Thread where the event occured.
        """
        # We can't assume the Process object will be in the System snapshot.
        # See the comments of get_process.
        tid     = self.get_tid()
        process = self.get_process()
        if process.has_thread(tid):
            thread = process.get_thread(tid)
        else:
            thread = Thread(tid)
            process._ThreadContainer__add_thread(thread)
        return thread

#==============================================================================

class ExceptionEvent (Event):
    """
    Exception event.
    
    @type exceptionName: dict( int S{->} str )
    @cvar exceptionName:
        Mapping of exception constants to their names.
    
    @type exceptionDescription: dict( int S{->} str )
    @cvar exceptionDescription:
        Mapping of exception constants to user-friendly strings.
    """

    eventName = 'Exception event'

    __exceptionName = {
        win32.EXCEPTION_ACCESS_VIOLATION          : 'EXCEPTION_ACCESS_VIOLATION',
        win32.EXCEPTION_ARRAY_BOUNDS_EXCEEDED     : 'EXCEPTION_ARRAY_BOUNDS_EXCEEDED',
        win32.EXCEPTION_BREAKPOINT                : 'EXCEPTION_BREAKPOINT',
        win32.EXCEPTION_DATATYPE_MISALIGNMENT     : 'EXCEPTION_DATATYPE_MISALIGNMENT',
        win32.EXCEPTION_FLT_DENORMAL_OPERAND      : 'EXCEPTION_FLT_DENORMAL_OPERAND',
        win32.EXCEPTION_FLT_DIVIDE_BY_ZERO        : 'EXCEPTION_FLT_DIVIDE_BY_ZERO',
        win32.EXCEPTION_FLT_INEXACT_RESULT        : 'EXCEPTION_FLT_INEXACT_RESULT',
        win32.EXCEPTION_FLT_INVALID_OPERATION     : 'EXCEPTION_FLT_INVALID_OPERATION',
        win32.EXCEPTION_FLT_OVERFLOW              : 'EXCEPTION_FLT_OVERFLOW',
        win32.EXCEPTION_FLT_STACK_CHECK           : 'EXCEPTION_FLT_STACK_CHECK',
        win32.EXCEPTION_FLT_UNDERFLOW             : 'EXCEPTION_FLT_UNDERFLOW',
        win32.EXCEPTION_ILLEGAL_INSTRUCTION       : 'EXCEPTION_ILLEGAL_INSTRUCTION',
        win32.EXCEPTION_IN_PAGE_ERROR             : 'EXCEPTION_IN_PAGE_ERROR',
        win32.EXCEPTION_INT_DIVIDE_BY_ZERO        : 'EXCEPTION_INT_DIVIDE_BY_ZERO',
        win32.EXCEPTION_INT_OVERFLOW              : 'EXCEPTION_INT_OVERFLOW',
        win32.EXCEPTION_INVALID_DISPOSITION       : 'EXCEPTION_INVALID_DISPOSITION',
        win32.EXCEPTION_NONCONTINUABLE_EXCEPTION  : 'EXCEPTION_NONCONTINUABLE_EXCEPTION',
        win32.EXCEPTION_PRIV_INSTRUCTION          : 'EXCEPTION_PRIV_INSTRUCTION',
        win32.EXCEPTION_SINGLE_STEP               : 'EXCEPTION_SINGLE_STEP',
        win32.EXCEPTION_STACK_OVERFLOW            : 'EXCEPTION_STACK_OVERFLOW',
        win32.EXCEPTION_GUARD_PAGE                : 'EXCEPTION_GUARD_PAGE',
        win32.EXCEPTION_INVALID_HANDLE            : 'EXCEPTION_INVALID_HANDLE',
        win32.EXCEPTION_POSSIBLE_DEADLOCK         : 'EXCEPTION_POSSIBLE_DEADLOCK',
        win32.CONTROL_C_EXIT                      : 'CONTROL_C_EXIT',
        win32.DBG_CONTROL_C                       : 'DBG_CONTROL_C',
        win32.MS_VC_EXCEPTION                     : 'MS_VC_EXCEPTION',
    }

    __exceptionDescription = {
        win32.EXCEPTION_ACCESS_VIOLATION          : 'Access violation',
        win32.EXCEPTION_ARRAY_BOUNDS_EXCEEDED     : 'Array bounds exceeded',
        win32.EXCEPTION_BREAKPOINT                : 'Breakpoint event',
        win32.EXCEPTION_DATATYPE_MISALIGNMENT     : 'Datatype misalignment',
        win32.EXCEPTION_FLT_DENORMAL_OPERAND      : 'Float denormal operand',
        win32.EXCEPTION_FLT_DIVIDE_BY_ZERO        : 'Float divide by zero',
        win32.EXCEPTION_FLT_INEXACT_RESULT        : 'Float inexact result',
        win32.EXCEPTION_FLT_INVALID_OPERATION     : 'Float invalid operation',
        win32.EXCEPTION_FLT_OVERFLOW              : 'Float overflow',
        win32.EXCEPTION_FLT_STACK_CHECK           : 'Float stack check',
        win32.EXCEPTION_FLT_UNDERFLOW             : 'Float underflow',
        win32.EXCEPTION_ILLEGAL_INSTRUCTION       : 'Illegal instruction',
        win32.EXCEPTION_IN_PAGE_ERROR             : 'In-page error',
        win32.EXCEPTION_INT_DIVIDE_BY_ZERO        : 'Integer divide by zero',
        win32.EXCEPTION_INT_OVERFLOW              : 'Integer overflow',
        win32.EXCEPTION_INVALID_DISPOSITION       : 'Invalid disposition',
        win32.EXCEPTION_NONCONTINUABLE_EXCEPTION  : 'Noncontinuable exception',
        win32.EXCEPTION_PRIV_INSTRUCTION          : 'Privileged instruction',
        win32.EXCEPTION_SINGLE_STEP               : 'Single step event',
        win32.EXCEPTION_STACK_OVERFLOW            : 'Stack limits overflow',
        win32.EXCEPTION_GUARD_PAGE                : 'Guard page hit',
        win32.EXCEPTION_INVALID_HANDLE            : 'Invalid handle',
        win32.EXCEPTION_POSSIBLE_DEADLOCK         : 'Possible deadlock',
        win32.CONTROL_C_EXIT                      : 'Control-C exit',
        win32.DBG_CONTROL_C                       : 'Debug Control-C',
        win32.MS_VC_EXCEPTION                     : 'Microsoft Visual C exception',
    }

    def get_exception_name(self):
        """
        @rtype:  str
        @return: Name of the exception as defined by the Win32 API.
        """
        code = self.get_exception_code()
        unk  = '0x%.8x' % code
        return self.__exceptionName.get(code, unk)

    def get_exception_description(self):
        """
        @rtype:  str
        @return: User-friendly name of the exception.
        """
        code = self.get_exception_code()
        unk  = 'C++ exception 0x%.8x' % code
        return self.__exceptionDescription.get(code, unk)

    def is_first_chance(self):
        """
        @rtype:  bool
        @return: True for first chance exceptions, False for last chance.
        """
        return self.raw.u.Exception.dwFirstChance != win32.FALSE

    def is_last_chance(self):
        """
        @rtype:  bool
        @return: The opposite of L{is_first_chance}.
        """
        return not self.is_first_chance()

    def is_noncontinuable(self):
        """
        @see: U{http://msdn.microsoft.com/en-us/library/aa363082(VS.85).aspx}
        
        @rtype:  bool
        @return: True if the exception is noncontinuable.
            
            Attempting to continue a noncontinuable exception results in an
            EXCEPTION_NONCONTINUABLE_EXCEPTION exception to be raised.
        """
        return bool( self.raw.u.Exception.ExceptionRecord.ExceptionFlags & \
                                            win32.EXCEPTION_NONCONTINUABLE )

    def is_continuable(self):
        """
        @rtype:  bool
        @return: The opposite of L{is_noncontinuable}.
        """
        return not self.is_noncontinuable()

    def get_exception_code(self):
        """
        @rtype:  int
        @return: Exception code as defined by the Win32 API.
        """
        return self.raw.u.Exception.ExceptionRecord.ExceptionCode

    def get_exception_address(self):
        """
        @rtype:  int
        @return: Memory address where the exception occured.
        """
        return self.raw.u.Exception.ExceptionRecord.ExceptionAddress

    def get_exception_information(self, index):
        """
        @type  index: int
        @param index: Index into the exception information block.
        
        @rtype:  int
        @return: Exception information DWORD.
        """
        if index < 0 or index > win32.EXCEPTION_MAXIMUM_PARAMETERS:
            raise IndexError, "Array index out of range: %s" % repr(index)
        info = self.raw.u.Exception.ExceptionRecord.ExceptionInformation
        return info[index]

    def get_exception_information_as_list(self):
        """
        @rtype:  list( int )
        @return: Exception information block.
        """
        info = self.raw.u.Exception.ExceptionRecord.ExceptionInformation
        return [ info[i] for i in xrange(0, win32.EXCEPTION_MAXIMUM_PARAMETERS) ]

    def get_access_violation_type(self):
        if self.get_exception_code() != win32.EXCEPTION_ACCESS_VIOLATION:
            msg = ("This method is only meaningful"
                   " for access violation exceptions.")
            raise Exception, msg
        return self.get_exception_information(0)

    def get_raw_exception_record_list(self):
        """
        Traverses the exception record linked list and builds a Python list.
        
        Nested exception records are received for nested exceptions. This
        happens when an exception is raised in the debugee while trying to
        handle a previous exception.
        
        @rtype:  list( L{EXCEPTION_RECORD} )
        @return:
            List of raw exception record structures as used by the Win32 API.
            
            There is always at least one exception record, so the list is
            never empty. All other methods of this class read from the first
            exception record only, that is, the most recent exception.
        """

        # The first EXCEPTION_RECORD is contained in EXCEPTION_DEBUG_INFO.
        record = self.raw.u.Exception.ExceptionRecord
        nested = [ record ]

        # The remaining EXCEPTION_RECORD structures are linked by pointers.
        while record.ExceptionRecord:
            record = record.ExceptionRecord.contents
            nested.append(record)

        # Return the list of nested exceptions.
        return nested

    # TODO
    # Return the nested exceptions as a list of ExceptionEvent objects.
    # The first element is always "self".
    # Each element contains a pointer to the next exception record.
    # New raw structures may have to be allocated for each object,
    # but it's OK to reuse pointers since they're supposed to be read only.
    # (Perhaps a custom DEBUG_EVENT has to be defined, where the first record
    # is a pointer instead of an embedded structure).
##    def get_nested_exceptions(self):

#==============================================================================

class CreateThreadEvent (Event):
    eventName = 'Thread creation event'

    def get_thread_handle(self):
        """
        @rtype:  L{ThreadHandle}
        @return: Thread handle received from the system.
            If it's a valid handle, a new L{ThreadHandle} object is created.
            Otherwise, the method returns INVALID_HANDLE_VALUE.
        @note: This method never returns NULL.
        """
        # The handle doesn't need to be closed.
        # See http://msdn.microsoft.com/en-us/library/ms681423(VS.85).aspx
        hThread = self.raw.u.CreateThread.hThread
        if hThread == win32.NULL:
            hThread = win32.INVALID_HANDLE_VALUE
        elif hThread != win32.INVALID_HANDLE_VALUE:
            hThread = ThreadHandle(hThread, False)
        return hThread

    def get_teb(self):
        """
        @rtype:  int
        @return: Pointer to the TEB.
        """
        return self.raw.u.CreateThread.lpThreadLocalBase

    def get_start_address(self):
        """
        @rtype:  int
        @return: Pointer to the first instruction to execute in this thread.
            
            Returns NULL when the debugger attached to a process and the thread
            already existed.
            
            See U{http://msdn.microsoft.com/en-us/library/ms679295(VS.85).aspx}
        """
        return self.raw.u.CreateThread.lpStartAddress

#==============================================================================

class CreateProcessEvent (Event):
    eventName = 'Process creation event'

    def get_file_handle(self):
        """
        @rtype:  L{FileHandle}
        @return: File handle to the main module.
            If it's a valid handle, a new L{FileHandle} object is created.
            Otherwise, the method returns INVALID_HANDLE_VALUE.
        @note: This method never returns NULL.
        """
        # This handle DOES need to be closed.
        # Therefore we must cache it so it doesn't
        # get closed after the first call.
        if hasattr(self, '_CreateProcessEvent__hFile'):
            hFile = self.__hFile
        else:
            hFile = self.raw.u.CreateProcessInfo.hFile
            if hFile == win32.NULL:
                hFile = win32.INVALID_HANDLE_VALUE
            elif hFile != win32.INVALID_HANDLE_VALUE:
                hFile = FileHandle(hFile, True)
            self.__hFile = hFile
        return hFile

    def get_process_handle(self):
        """
        @rtype:  L{ProcessHandle}
        @return: Process handle received from the system.
            If it's a valid handle, a new L{ProcessHandle} object is created.
            Otherwise, the method returns INVALID_HANDLE_VALUE.
        @note: This method never returns NULL.
        """
        # The handle doesn't need to be closed.
        # See http://msdn.microsoft.com/en-us/library/ms681423(VS.85).aspx
        hProcess = self.raw.u.CreateProcessInfo.hProcess
        if hProcess == win32.NULL:
            hProcess = win32.INVALID_HANDLE_VALUE
        elif hProcess != win32.INVALID_HANDLE_VALUE:
            hProcess = ProcessHandle(hProcess, False)
        return hProcess

    def get_thread_handle(self):
        """
        @rtype:  L{ThreadHandle}
        @return: Thread handle received from the system.
            If it's a valid handle, a new L{ThreadHandle} object is created.
            Otherwise, the method returns INVALID_HANDLE_VALUE.
        @note: This method never returns NULL.
        """
        # The handle doesn't need to be closed.
        # See http://msdn.microsoft.com/en-us/library/ms681423(VS.85).aspx
        hThread = self.raw.u.CreateProcessInfo.hThread
        if hThread == win32.NULL:
            hThread = win32.INVALID_HANDLE_VALUE
        elif hThread != win32.INVALID_HANDLE_VALUE:
            hThread = ThreadHandle(hThread, False)
        return hThread

    def get_start_address(self):
        """
        @rtype:  int
        @return: Pointer to the first instruction to execute in this process.
            
            Returns NULL when the debugger attaches to a process.
            
            See U{http://msdn.microsoft.com/en-us/library/ms679295(VS.85).aspx}
        """
        return self.raw.u.CreateProcessInfo.lpStartAddress

    def get_image_base(self):
        """
        @rtype:  int
        @return: Base address of the main module.
        """
        return self.raw.u.CreateProcessInfo.lpBaseOfImage

    def get_teb(self):
        """
        @rtype:  int
        @return: Pointer to the TEB.
        """
        return self.raw.u.CreateProcessInfo.lpThreadLocalBase

    def get_debug_info(self):
        """
        @rtype:  str
        @return: Debugging information.
        """
        raw  = self.raw.u.CreateProcessInfo
        ptr  = raw.lpBaseOfImage + raw.dwDebugInfoFileOffset
        size = raw.nDebugInfoSize
        data = self.get_process().peek(ptr, size)
        if len(data) == size:
            return data
        return None

    def get_filename(self):
        """
        @rtype:  str, None
        @return: This method does it's best to retrieve the filename to
        the main module of the process. However, sometimes that's not
        possible, and None is returned instead.
        """

        # Try to get the filename from the file handle.
        szFilename = self.get_file_handle().get_filename()
        if not szFilename:

            # Try to get it from CREATE_PROCESS_DEBUG_INFO.lpImageName
            # It's NULL or *NULL most of the times, see MSDN:
            # http://msdn.microsoft.com/en-us/library/ms679286(VS.85).aspx
            aProcess = self.get_process()
            lpRemoteFilenamePtr = self.raw.u.CreateProcessInfo.lpImageName
            if lpRemoteFilenamePtr:
                lpFilename  = aProcess.peek_uint(lpRemoteFilenamePtr)
                fUnicode    = self.raw.u.CreateProcessInfo.fUnicode
                szFilename  = aProcess.peek_string(lpFilename, fUnicode)

            # Try to get it from Process.get_image_name().
            if not szFilename:
                szFilename = aProcess.get_image_name()

        # Return the filename, or None on error.
        return szFilename

    def get_module_base(self):
        """
        @rtype:  int
        @return: Base address of the main module.
        """
        return self.get_image_base()

    def get_module(self):
        """
        @rtype:  L{Module}
        @return: Main module of the process.
        """
        return self.get_process().get_module( self.get_module_base() )

#==============================================================================

class ExitThreadEvent (Event):
    eventName = 'Thread termination event'

    def get_exit_code(self):
        """
        @rtype:  int
        @return: Exit code of the thread.
        """
        return self.raw.u.ExitThread.dwExitCode

#==============================================================================

class ExitProcessEvent (Event):
    eventName = 'Process termination event'

    def get_exit_code(self):
        """
        @rtype:  int
        @return: Exit code of the process.
        """
        return self.raw.u.ExitProcess.dwExitCode

#==============================================================================

class LoadDLLEvent (Event):
    eventName = 'Module load event'

    def get_module_base(self):
        """
        @rtype:  int
        @return: Base address for the newly loaded DLL.
        """
        return self.raw.u.LoadDll.lpBaseOfDll

    def get_module(self):
        """
        @rtype:  L{Module}
        @return: Module object for the newly loaded DLL.
        """
        return self.get_process().get_module( self.get_module_base() )

    def get_file_handle(self):
        """
        @rtype:  L{FileHandle}
        @return: File handle to the newly loaded DLL.
            If it's a valid handle, a new L{FileHandle} object is created.
            Otherwise, the method returns INVALID_HANDLE_VALUE.
        @note: This method never returns NULL.
        """
        # This handle DOES need to be closed.
        # Therefore we must cache it so it doesn't
        # get closed after the first call.
        if hasattr(self, '_CreateProcessEvent__hFile'):
            hFile = self.__hFile
        else:
            hFile = self.raw.u.LoadDll.hFile
            if hFile == win32.NULL:
                hFile = win32.INVALID_HANDLE_VALUE
            elif hFile != win32.INVALID_HANDLE_VALUE:
                hFile = FileHandle(hFile, True)
            self.__hFile = hFile
        return hFile

    def get_filename(self):
        """
        @rtype:  str, None
        @return: This method does it's best to retrieve the filename to
        the newly loaded module. However, sometimes that's not
        possible, and None is returned instead.
        """

        # Try to get the filename from the file handle.
        szFilename = self.get_file_handle().get_filename()
        if not szFilename:

            # Try to get it from LOAD_DLL_DEBUG_INFO.lpImageName
            # It's NULL or *NULL most of the times, see MSDN:
            # http://msdn.microsoft.com/en-us/library/ms679286(VS.85).aspx
            aProcess = self.get_process()
            lpRemoteFilenamePtr = self.raw.u.LoadDll.lpImageName
            if lpRemoteFilenamePtr:
                lpFilename  = aProcess.peek_uint(lpRemoteFilenamePtr)
                fUnicode    = self.raw.u.LoadDll.fUnicode
                szFilename  = aProcess.peek_string(lpFilename, fUnicode)
                if not szFilename:
                    szFilename = None

        # Return the filename, or None on error.
        return szFilename

#==============================================================================

class UnloadDLLEvent (Event):
    eventName = 'Module unload event'

    def get_module_base(self):
        """
        @rtype:  int
        @return: Base address for the recently unloaded DLL.
        """
        return self.raw.u.UnloadDll.lpBaseOfDll

    def get_module(self):
        """
        @rtype:  L{Module}
        @return: Module object for the recently unloaded DLL.
        """
        return self.get_process().get_module( self.get_module_base() )

#==============================================================================

class OutputDebugStringEvent (Event):
    eventName = 'Debug string output event'

    def get_debug_string(self):
        """
        @rtype:  str, unicode
        @return: String sent by the debugee.
            It may be ANSI or Unicode and may end with a null character.
        """
        return self.get_process().peek_string(
                                    self.raw.u.DebugString.lpDebugStringData,
                                    self.raw.u.DebugString.fUnicode,
                                    self.raw.u.DebugString.nDebugStringLength)

#==============================================================================

class RIPEvent (Event):
    eventName = 'RIP event'

    def get_rip_error(self):
        """
        @rtype:  int
        @return: RIP error code as defined by the Win32 API.
        """
        return self.raw.u.RipInfo.dwError

    def get_rip_type(self):
        """
        @rtype:  int
        @return: RIP type code as defined by the Win32 API.
        """
        return self.raw.u.RipInfo.dwType

#==============================================================================

class EventFactory (object):
    """
    Factory of L{Event} objects.
    
    @type baseEvent: L{Event}
    @cvar baseEvent:
        Base class for Event objects.
        It's used for unknown event codes.
    
    @type eventClasses: dict( int S{->} L{Event} )
    @cvar eventClasses:
        Dictionary that maps event codes to L{Event} subclasses.
    """

    baseEvent    = Event
    eventClasses = {
        win32.EXCEPTION_DEBUG_EVENT       : ExceptionEvent,           # 1
        win32.CREATE_THREAD_DEBUG_EVENT   : CreateThreadEvent,        # 2
        win32.CREATE_PROCESS_DEBUG_EVENT  : CreateProcessEvent,       # 3
        win32.EXIT_THREAD_DEBUG_EVENT     : ExitThreadEvent,          # 4
        win32.EXIT_PROCESS_DEBUG_EVENT    : ExitProcessEvent,         # 5
        win32.LOAD_DLL_DEBUG_EVENT        : LoadDLLEvent,             # 6
        win32.UNLOAD_DLL_DEBUG_EVENT      : UnloadDLLEvent,           # 7
        win32.OUTPUT_DEBUG_STRING_EVENT   : OutputDebugStringEvent,   # 8
        win32.RIP_EVENT                   : RIPEvent,                 # 9
    }

    @classmethod
    def get(cls, debug, raw):
        """
        @type  debug: L{Debug}
        @param debug: Debug object that received the event.
        
        @type  raw: L{DEBUG_EVENT}
        @param raw: Raw DEBUG_EVENT structure as used by the Win32 API.
        
        @rtype: L{Event}
        @returns: An Event object or one of it's subclasses,
            depending on the event type.
        """
        eventClass = cls.eventClasses.get(raw.dwDebugEventCode, cls.baseEvent)
        return eventClass(debug, raw)

    def __new__(typ, *args, **kwargs):
        """
        EventFactory is a singleton, you can't really have multiple
        instances of it. To create this effect, the __new__ operator
        was overriden to return always the B{class} object instead
        of new I{instances}.
        """
        return EventFactory

#==============================================================================

class EventHandler (object):
    """
    Base class for debug event handlers.
    
    Your program should subclass it to implement it's own event handling.
    
    The signature for event handlers is the following::
        
        def event_handler(self, event):
    
    Where B{event} is an L{Event} object.
    
    Each event handler is named after the event they handle.
    This is the list of all valid event handler names:
    
     - event:
       
       Receives an L{Event} object or an object of any of it's subclasses,
       and handles any event for which no handler was defined.
       
     - unknown_event:
       
       Receives an L{Event} object or an object of any of it's subclasses,
       and handles any event unknown to the debugging engine. (This is not
       likely to happen unless the Win32 debugging API is changed in future
       versions of Windows).
       
     - exception
       
       Receives an L{ExceptionEvent} object and handles any exception for
       which no handler was defined. See above for exception handlers.
       
     - unknown_exception
       
       Receives an L{ExceptionEvent} object and handles any exception unknown
       to the debugging engine. This usually happens for C++ exceptions, which
       are not standardized and may change from one compiler to the next.
       
       Currently we have partial support for C++ exceptions thrown by Microsoft
       compilers.
       
       Also see: U{RaiseException<http://msdn.microsoft.com/en-us/library/ms680552(VS.85).aspx>}
       
     - create_thread
       
       Receives a L{CreateThreadEvent} object.
       
     - create_process
       
       Receives a L{CreateProcessEvent} object.
       
     - exit_thread
       
       Receives a L{ExitThreadEvent} object.
       
     - exit_process
       
       Receives a L{ExitProcessEvent} object.
       
     - load_dll
       
       Receives a L{LoadDLLEvent} object.
       
     - unload_dll
       
       Receives an L{UnloadDLLEvent} object.
       
     - output_string
       
       Receives an L{OutputDebugStringEvent} object.
       
     - rip
       
       Receives a L{RIPEvent} object.
       
    This is the list of all valid exception handler names
    (they all receive an L{ExceptionEvent} object):
    
     - access_violation
     - array_bounds_exceeded
     - breakpoint
     - control_c_exit
     - datatype_misalignment
     - debug_control_c
     - float_denormal_operand
     - float_divide_by_zero
     - float_inexact_result
     - float_invalid_operation
     - float_overflow
     - float_stack_check
     - float_underflow
     - guard_page
     - illegal_instruction
     - in_page_error
     - integer_divide_by_zero
     - integer_overflow
     - invalid_disposition
     - invalid_handle
     - ms_vc_exception
     - noncontinuable_exception
     - possible_deadlock
     - privileged_instruction
     - single_step
     - stack_overflow
    
    
    
    @type apiHooks: dict( str S{->} tuple( str, int ) )
    @cvar apiHooks:
        Dictionary that maps module names to tuples of ( procedure name, parameter count ).
        
        All procedures listed here will be hooked for calls from the debuguee.
        When this happens, the corresponding event handler is notified both
        when the procedure is entered and when it's left by the debugee.
        
        For example, if the procedure name is "LoadLibraryEx" the event handler
        routines must be defined as "pre_LoadLibraryEx" and "post_LoadLibraryEx"
        in your class.
        
        The signature for the routines can be something like this::
            
            def pre_LoadLibraryEx(event, *params):
                ra   = params[0]        # return address
                argv = params[1:]       # function parameters
                
                # (...)
            
            def post_LoadLibrary(event, return_value):
                
                # (...)
        
        But since you can also specify the number of arguments, this signature
        works too (four arguments in this case)::
            
            def pre_LoadLibraryEx(event, ra, lpFilename, hFile, dwFlags):
                szFilename = event.get_process().peek_string(lpFilename)
                
                # (...)
        
        Note that the number of parameters to pull from the stack includes the
        return address. The apiHooks dictionary for the example above would
        look like this::
            
            apiHook = {
                
                "kernel32.dll" : (
                    
                    #   Procedure name      Parameter count
                    (   "LoadLibraryEx",    4 ),
                    
                    # (more procedures can go here...)
                ),
                
                # (more libraries can go here...)
            }
    """

#------------------------------------------------------------------------------

    # Dispatch mechanism.

    # Map of event code constants to the names of the user-defined methods.
    # Unknown codes go to 'unknown_event'.
    __eventCallbackName = {
        win32.EXCEPTION_DEBUG_EVENT       : 'exception',              # 1
        win32.CREATE_THREAD_DEBUG_EVENT   : 'create_thread',          # 2
        win32.CREATE_PROCESS_DEBUG_EVENT  : 'create_process',         # 3
        win32.EXIT_THREAD_DEBUG_EVENT     : 'exit_thread',            # 4
        win32.EXIT_PROCESS_DEBUG_EVENT    : 'exit_process',           # 5
        win32.LOAD_DLL_DEBUG_EVENT        : 'load_dll',               # 6
        win32.UNLOAD_DLL_DEBUG_EVENT      : 'unload_dll',             # 7
        win32.OUTPUT_DEBUG_STRING_EVENT   : 'output_string',          # 8
        win32.RIP_EVENT                   : 'rip',                    # 9
    }

    # Map of exception code constants to the names of the user-defined methods.
    # Unknown codes go to 'unknown_exception'.
    __exceptionCallbackName = {
        win32.EXCEPTION_ACCESS_VIOLATION          : 'access_violation',
        win32.EXCEPTION_ARRAY_BOUNDS_EXCEEDED     : 'array_bounds_exceeded',
        win32.EXCEPTION_BREAKPOINT                : 'breakpoint',
        win32.EXCEPTION_DATATYPE_MISALIGNMENT     : 'datatype_misalignment',
        win32.EXCEPTION_FLT_DENORMAL_OPERAND      : 'float_denormal_operand',
        win32.EXCEPTION_FLT_DIVIDE_BY_ZERO        : 'float_divide_by_zero',
        win32.EXCEPTION_FLT_INEXACT_RESULT        : 'float_inexact_result',
        win32.EXCEPTION_FLT_INVALID_OPERATION     : 'float_invalid_operation',
        win32.EXCEPTION_FLT_OVERFLOW              : 'float_overflow',
        win32.EXCEPTION_FLT_STACK_CHECK           : 'float_stack_check',
        win32.EXCEPTION_FLT_UNDERFLOW             : 'float_underflow',
        win32.EXCEPTION_ILLEGAL_INSTRUCTION       : 'illegal_instruction',
        win32.EXCEPTION_IN_PAGE_ERROR             : 'in_page_error',
        win32.EXCEPTION_INT_DIVIDE_BY_ZERO        : 'integer_divide_by_zero',
        win32.EXCEPTION_INT_OVERFLOW              : 'integer_overflow',
        win32.EXCEPTION_INVALID_DISPOSITION       : 'invalid_disposition',
        win32.EXCEPTION_NONCONTINUABLE_EXCEPTION  : 'noncontinuable_exception',
        win32.EXCEPTION_PRIV_INSTRUCTION          : 'privileged_instruction',
        win32.EXCEPTION_SINGLE_STEP               : 'single_step',
        win32.EXCEPTION_STACK_OVERFLOW            : 'stack_overflow',
        win32.EXCEPTION_GUARD_PAGE                : 'guard_page',
        win32.EXCEPTION_INVALID_HANDLE            : 'invalid_handle',
        win32.EXCEPTION_POSSIBLE_DEADLOCK         : 'possible_deadlock',
        win32.CONTROL_C_EXIT                      : 'control_c_exit',
        win32.DBG_CONTROL_C                       : 'debug_control_c',
        win32.MS_VC_EXCEPTION                     : 'ms_vc_exception',
    }

    # Default (empty) API hooks dictionary.
    apiHooks = {}

    def __init__(self):
        # Convert the tuples into instances of the ApiHook class.
        # A new dictionary must be instanced, otherwise we could also be
        #  affecting all other instances of the EventHandler.
        new_apiHooks = dict()
        for lib, hooks in self.apiHooks.iteritems():
            new_apiHooks[lib] = [ ApiHook(self, *h) for h in hooks ]
        self.apiHooks = new_apiHooks

    def __setApiHooksForDll(self, event):
        """
        Hook the requested API calls (in self.apiHooks).
        
        This method must be called whenever a DLL is loaded.
        """
        if self.apiHooks:
            fileName = event.get_module().get_filename()
            if fileName:
                lib_name = FileHandle.pathname_to_filename(fileName).lower()
                for hook_lib, hook_api_list in self.apiHooks.iteritems():
                    if hook_lib == lib_name:
                        for hook_api_stub in hook_api_list:
                            hook_api_stub.hook(event.debug, event.get_pid(),
                                                                      lib_name)

    def __call__(self, event):
        """
        Dispatch debug events.
        
        @type  event: L{Event}
        @param event: Event object.
        """
        eventCode = event.get_code()

        # Try to find an override for the event type.
        # If not found use the generic "event" method.
        methodName = self.__eventCallbackName.get(eventCode, 'unknown_event')
        method = getattr(self, methodName, self.event)

        # If it's an exception, try to find an override for the exception type.
        # If not found use the method from the previous step.
        if eventCode == win32.EXCEPTION_DEBUG_EVENT:
            methodName = self.__exceptionCallbackName.get(
                                event.get_exception_code(),
                                'unknown_exception'
                                )
            method = getattr(self, methodName, method)

        # If it's a load dll event, set the requested API hooks.
        elif eventCode == win32.LOAD_DLL_DEBUG_EVENT:
            self.__setApiHooksForDll(event)

        # Call the callback method found.
        return method(event)

    def event(self, event):
        """
        Handler for events not handled by any other defined method.

        @type  event: L{Event}
        @param event: Event object.
        """
        pass

#==============================================================================

class EventDispatcher (object):
    """
    Implements debug event dispatching capabilities.
    """

    # Maps event code constants to the names of the pre-notify routines.
    # These routines are called BEFORE the user-defined handlers.
    # Unknown codes are ignored.
    __preEventNotifyCallbackName = {
        win32.CREATE_THREAD_DEBUG_EVENT   : 'notify_create_thread',
        win32.CREATE_PROCESS_DEBUG_EVENT  : 'notify_create_process',
        win32.LOAD_DLL_DEBUG_EVENT        : 'notify_load_dll',
    }

    # Maps event code constants to the names of the post-notify routines.
    # These routines are called AFTER the user-defined handlers.
    # Unknown codes are ignored.
    __postEventNotifyCallbackName = {
        win32.EXIT_THREAD_DEBUG_EVENT     : 'notify_exit_thread',
        win32.EXIT_PROCESS_DEBUG_EVENT    : 'notify_exit_process',
        win32.UNLOAD_DLL_DEBUG_EVENT      : 'notify_unload_dll',
        win32.RIP_EVENT                   : 'notify_rip',
    }

    # Maps exception code constants to the names of the pre-notify routines.
    # These routines are called BEFORE the user-defined handlers.
    # Unknown codes are ignored.
    __preExceptionNotifyCallbackName = {
        win32.EXCEPTION_BREAKPOINT                : 'notify_breakpoint',
        win32.EXCEPTION_SINGLE_STEP               : 'notify_single_step',
        win32.EXCEPTION_GUARD_PAGE                : 'notify_guard_page',
        win32.DBG_CONTROL_C                       : 'notify_debug_control_c',
        win32.MS_VC_EXCEPTION                     : 'notify_ms_vc_exception',
    }

    # Maps exception code constants to the names of the post-notify routines.
    # These routines are called AFTER the user-defined handlers.
    # Unknown codes are ignored.
    __postExceptionNotifyCallbackName = {
    }

    def __init__(self, eventHandler):
        """
        Event dispatcher.
        
        @type  eventHandler: L{EventHandler}
        @param eventHandler: Event handler object.

        @note: The L{eventHandler} parameter may be any callable Python object
            (for example a function, or an instance method).
            However you'll probably find it more convenient to use an instance
            of a subclass of L{EventHandler} here.
        """
        self.__eventHandler = eventHandler

    def dispatch(self, event):
        """
        Sends event notifications to the L{Debug} object and
        the L{EventHandler} object provided by the user.

        The L{Debug} object will forward the notifications to it's contained
        snapshot objects (L{System}, L{Process}, L{Thread} and L{Module}) when
        appropriate.

        @warning: This method is called automatically from L{Debug.dispatch}.

        @see: L{Debug.cont}, L{Debug.loop}, L{Debug.wait}

        @type  event: L{Event}
        @param event: Event object passed to L{Debug.dispatch}.

        @raise WindowsError: Raises an exception on error.
        """
        returnValue  = None
        bCallHandler = True
        pre_handler  = None
        post_handler = None
        eventCode    = event.get_code()

        # Get the pre and post notification methods for exceptions.
        # If not found, the following steps take care of that.
        if eventCode == win32.EXCEPTION_DEBUG_EVENT:
            exceptionCode = event.get_exception_code()
            pre_name      = self.__preExceptionNotifyCallbackName.get(
                                                           exceptionCode, None)
            post_name     = self.__postExceptionNotifyCallbackName.get(
                                                           exceptionCode, None)
            if  pre_name     is not None:
                pre_handler  = getattr(self, pre_name,  None)
            if  post_name    is not None:
                post_handler = getattr(self, post_name, None)

        # Get the pre notification method for all other events.
        # This includes the exception event if no notify method was found
        # for this exception code.
        if pre_handler is None:
            pre_name = self.__preEventNotifyCallbackName.get(eventCode, None)
            if  pre_name is not None:
                pre_handler = getattr(self, pre_name, pre_handler)

        # Get the post notification method for all other events.
        # This includes the exception event if no notify method was found
        # for this exception code.
        if post_handler is None:
            post_name = self.__postEventNotifyCallbackName.get(eventCode, None)
            if  post_name is not None:
                post_handler = getattr(self, post_name, post_handler)

        # Call the pre-notify method only if it was defined.
        # If an exception is raised don't call the other methods.
        if pre_handler is not None:
            bCallHandler = pre_handler(event)

        # Call the user-defined event handler only if the pre-notify
        #  method was defined and returned True.
        try:
            if bCallHandler and self.__eventHandler is not None:
                returnValue = self.__eventHandler(event)

        # Call the post-notify method if defined, even if an exception is
        #  raised by the user-defined event handler.
        finally:
            if post_handler is not None:
                post_handler(event)

        # Return the value from the call to the user-defined event handler.
        # If not defined return None.
        return returnValue

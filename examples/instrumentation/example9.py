# Example #9
# http://apps.sourceforge.net/trac/winappdbg/wiki/wiki/Instrumentation#Example9:printathreadscodedisassembly

from winappdbg import Thread, CrashDump, System

def print_thread_disassembly( tid ):
    
    # Request debug privileges
    System.request_debug_privileges()
    
    # Instance a Thread object
    thread = Thread( tid )
    
    # Suspend the thread execution
    thread.suspend()
    
    # Get the thread's currently running code
    try:
        eip  = thread.get_pc()
        code = thread.disassemble_around( eip )
        
        # You can also do this:
        # code = thread.disassemble_around_pc()
    
    # Resume the thread execution
    finally:
        thread.resume()
    
    # Display the thread context
    print
    print CrashDump.dump_code( code, eip ),

# When invoked from the command line,
# the first argument is a thread ID
# (use example3.py to enumerate threads)
if __name__ == "__main__":
    import sys
    tid = int( sys.argv[1] )
    print_thread_disassembly( tid )

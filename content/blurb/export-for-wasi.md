
# REQUIRED
title = "export"

# OPTIONAL
description = "implementation of the handler interface"
template = "blurb"

[extra]
date = "2023-06-18T23:59:19Z"

---

  I. What is the minimum required to implement the handler?

  X. From the C files in the Spin SDK for Golang
     A. Already exercised indirectly with TinyGo implementations for the handler
     B. Which gave us the familiarity with Redis calls, and construction of HTTP signatures  (while postponed pkcs1 verify)
 XI. WASI more directly by rewriting with Zig
     A. 3 exports are named in the C files
        1. handler
        2. realloc
        3. free
     B. First attempt is by using Zig's build system to include the C files which works 
     C. That naturally led to the question Can we write Zig to call Spin API without C?
        1. `zig translate-c`
        2. Note that RET_AREA has different size for Spin calls
        3. The memory ownership causes arena.deinit error string pointer/length out of bounds

 
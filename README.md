<h1 align="center">🎭 ProcHerp</h1>

<p align="center">
<b>Low-Level Process Herpaderping & NTAPI Research Framework</b><br>
Windows Internals · Native NTAPI · Disk–Memory Discrepancy Abuse
</p>

<p align="center">
<img src="https://img.shields.io/badge/Language-C-blue?style=for-the-badge">
<img src="https://img.shields.io/badge/Platform-Windows-informational?style=for-the-badge">
<img src="https://img.shields.io/badge/Architecture-x64-important?style=for-the-badge">
<img src="https://img.shields.io/badge/Technique-Process_Herpaderping-red?style=for-the-badge">
</p>

<hr>

<h2>📌 Executive Summary</h2>

<p>
<b>PhantomHerpa</b> is a low-level Windows internals research project that demonstrates the <b>Process Herpaderping</b> technique — a stealthy process creation method that exploits a discrepancy between a file’s on-disk representation and its executable image mapped in memory.
</p>

<p>
Unlike traditional injection or hollowing techniques, this approach leverages native Windows behavior using <b>direct NTAPI calls</b> to execute a payload while maintaining a fully legitimate executable image on disk.
</p>

<hr>

<h2>🎭 Core Technique: Process Herpaderping</h2>

<p>
Process Herpaderping abuses the separation between <b>file objects</b> and <b>image sections</b> inside the Windows kernel.
The execution flow is broken into distinct, surgical stages:
</p>

<ul>
<li><b>Stage 1 – The Bait:</b><br>
A temporary file (<code>.tmp</code>) is created and populated with the controlled payload.</li>

<li><b>Stage 2 – The Mapping:</b><br>
An executable image section is created via <code>NtCreateSection</code> using the <code>SEC_IMAGE</code> flag.  
At this point, Windows snapshots the payload into memory.</li>

<li><b>Stage 3 – The Creation:</b><br>
A new process object is instantiated using <code>NtCreateProcessEx</code>, backed by the previously created image section.</li>

<li><b>Stage 4 – The Switch:</b><br>
Before execution begins, the temporary file on disk is overwritten with a fully legitimate Windows binary (e.g. <code>winload.exe</code>).</li>

<li><b>Stage 5 – The Illusion:</b><br>
Any inspection of the executable file on disk shows a trusted image, while the memory-resident code executing belongs entirely to the original payload.</li>
</ul>

<hr>

<h2>🏗️ Software Architecture</h2>

<p>
The project was intentionally engineered with a <b>clean and modular internal layout</b>, despite being deliverable as a single-file PoC when needed.
</p>

<ul>
<li><b>Decoupled Components:</b><br>
Hashing, file operations, NTAPI resolution, PE parsing, and process logic are isolated from one another.</li>

<li><b>Extensible Design:</b><br>
The structure allows seamless expansion into additional techniques such as <b>Process Ghosting</b> or <b>Doppelgänging</b>.</li>

<li><b>Symbol & Variable Obfuscation:</b><br>
Non-standard naming conventions reduce static pattern recognition and signature-based detection.</li>
</ul>

<hr>

<h2>👻 Stealth & Anti-Analysis Features</h2>

<ul>
<li><b>Dynamic API Resolution (DJB2):</b><br>
No suspicious functions are statically imported. All APIs are resolved at runtime via hash-based export walking, keeping the Import Address Table clean.</li>

<li><b>Direct NTAPI Invocation:</b><br>
All critical operations bypass <code>kernel32.dll</code> and communicate directly with <code>ntdll.dll</code>, reducing exposure to user-mode hooks.</li>

<li><b>PEB & Process Parameter Forging:</b><br>
The remote process environment, command line, and image path are manually reconstructed to appear fully legitimate under inspection tools.</li>
</ul>

<hr>

<h2>🧠 Memory & Process Management</h2>

<ul>
<li>Manual allocation and injection of process parameters via <code>NtAllocateVirtualMemory</code> and <code>NtWriteVirtualMemory</code>.</li>
<li>Environment block reconstruction for native-looking process initialization.</li>
<li>Execution is started explicitly at the real payload entry point using <code>NtCreateThreadEx</code>.</li>
</ul>

<hr>

<h2>🎯 Research Objectives</h2>

<ul>
<li>Study kernel behavior around <code>SEC_IMAGE</code> backed sections.</li>
<li>Observe EDR responses to disk-memory desynchronization.</li>
<li>Analyze process validation mechanisms relying on on-disk inspection.</li>
<li>Refine stealthy process creation without traditional hollowing.</li>
</ul>

<hr>

<h2>⚠️ Legal & Ethical Disclaimer</h2>

<p>
This project is intended strictly for <b>educational and security research purposes</b>.
It is designed for malware analysts, reverse engineers, and Windows internals researchers.
</p>

<p>
The author does not condone misuse and is not responsible for any illegal or unethical application of this code.
</p>

<hr>

<p align="center">
<b>Researcher:</b> BassamHossam (0xUFO)<br>
</p>

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
<b>ProcHerp</b> is a low-level Windows internals research project that demonstrates the
<b>Process Herpaderping</b> technique — a stealthy process creation method abusing
the discrepancy between a file’s on-disk representation and its executable image
mapped into memory.
</p>

<p>
The project relies entirely on <b>native NTAPI calls</b>, avoiding high-level Win32
abstractions and showcasing how legitimate Windows behavior can be repurposed
to achieve deceptive execution semantics.
</p>

<hr>

<h2>🎭 Core Technique: Process Herpaderping</h2>

<ul>
<li><b>Stage 1 – The Bait:</b><br>
A temporary file is created and populated with a controlled payload.</li>

<li><b>Stage 2 – The Mapping:</b><br>
<code>NtCreateSection</code> is invoked with <code>SEC_IMAGE</code>, causing the kernel to
snapshot the payload into memory.</li>

<li><b>Stage 3 – The Creation:</b><br>
A process object is instantiated using <code>NtCreateProcessEx</code> backed by the image section.</li>

<li><b>Stage 4 – The Switch:</b><br>
The on-disk file is overwritten with a fully legitimate executable before execution.</li>

<li><b>Stage 5 – The Illusion:</b><br>
Disk inspection shows a trusted binary, while memory executes the original payload.</li>
</ul>

<hr>

<h2>🏗️ Software Architecture</h2>

<ul>
<li><b>Decoupled Design:</b> Hashing, NTAPI resolution, file handling, and process logic are isolated.</li>
<li><b>Extensible Layout:</b> Easily expandable into Ghosting, Doppelgänging, or hybrid loaders.</li>
<li><b>Obfuscation-Friendly:</b> Non-standard symbols and variable naming reduce static signatures.</li>
</ul>

<hr>

<h2>👻 Stealth & Anti-Analysis</h2>

<ul>
<li><b>Dynamic API Resolution (DJB2):</b> Zero suspicious static imports.</li>
<li><b>Direct NTAPI Calls:</b> Bypasses user-mode hooks in <code>kernel32.dll</code>.</li>
<li><b>PEB & Parameters Forging:</b> Legitimate-looking image path and command line.</li>
</ul>

<hr>

<h2>🧠 Memory & Process Management</h2>

<ul>
<li>Manual process parameter and environment block construction.</li>
<li>Memory operations via <code>NtAllocateVirtualMemory</code> and <code>NtWriteVirtualMemory</code>.</li>
<li>Execution initiated using <code>NtCreateThreadEx</code> at the real payload entry point.</li>
</ul>

<hr>

<h2>▶️ Proof of Concept (PoC)</h2>

<p>
The following demonstration shows <b>ProcHerp</b> successfully creating and executing
a herpaderped process while maintaining a fully legitimate on-disk image.
</p>

<pre>
ProcHerp.exe &lt;LegitimateBinary.exe&gt; &lt;Payload.exe&gt;
</pre>

<p align="center">
<img src="poc_execution.gif" alt="ProcHerp PoC Execution" width="85%">
<br>
<i>Figure 1: End-to-end execution flow demonstrating disk–memory discrepancy abuse.</i>
</p>

<hr>

<h2>🪟 Payload Verification (User Perspective)</h2>

<p>
From a user and tool inspection standpoint, the payload appears as a
<b>legitimate Microsoft-verified process</b>, despite executing entirely different
code in memory.
</p>

<p align="center">
<img src="messagebox_verified.png" alt="Microsoft Verified MessageBox" width="60%">
<br>
<i>Figure 2: MessageBox displayed from a herpaderped process appearing as a trusted binary.</i>
</p>

<hr>

<h2>🎯 Research Objectives</h2>

<ul>
<li>Study kernel behavior around <code>SEC_IMAGE</code> sections.</li>
<li>Analyze EDR detection gaps caused by disk–memory desynchronization.</li>
<li>Explore stealthy alternatives to classic process hollowing.</li>
</ul>

<hr>

<h2>⚠️ Legal & Ethical Disclaimer</h2>

<p>
This project is intended strictly for <b>educational and security research purposes</b>.
It is designed for malware analysts, reverse engineers, and Windows internals researchers.
</p>

<p>
The author does not condone misuse and is not responsible for any illegal or unethical
application of this code.
</p>

<hr>

<p align="center">
<b>Researcher:</b> BassamHossam (0xUFO)
</p>

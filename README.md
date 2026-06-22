
# FMEM - Windows 11 Physical Memory Carver

FMEM is a specialized Python-based memory forensics framework designed to parse and carve active processes, metadata, and kernel structures directly from raw physical memory dumps. Built to support deep forensic incident response workflows, it handles modern system behaviors like Kernel Address Space Layout Randomization (KASLR) and page table faults.

---

## 🚀 Key Features

* Raw Memory Carving Engine: Scans and extracts process tables, active threads, and related metadata directly from raw binary memory images.
* KASLR Bypass Layer: Employs programmatic heuristic analysis to bypass Windows Kernel Address Space Layout Randomization.
* Fault-Tolerant Translation: Handles and isolates page table faults during physical-to-virtual address translation.
* Intuitive GUI Platform: Includes a built-in desktop application (FmemGui) to load, scan, search, and export extracted artifacts seamlessly.

---

## 📁 Repository Structure

* fmem/ — Core framework package (context management, translation layers, plugin registration, memory scanners, and kernel structures).
* memoryf/ — Extended utility components for custom analysis extensions.
* main.py — Main terminal entry point for CLI-driven analysis.
* gui.py — Main desktop launch script (Instantiates FmemGui).

---

## ⚙️ Installation & Setup

1. Clone the Repository:
`bash
   git clone [https://github.com/mortdaabbas/memory-forensics-tool.git](https://github.com/mortdaabbas/memory-forensics-tool.git)
   cd memory-forensics-tool
2. Set up the Virtual Environment
  python -m venv .venv
   .\.venv\Scripts\Activate.ps1
3. Run the Application
   python gui.py

4.CMD
  python main.py 
  


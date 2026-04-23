// eac_popup_mover.cs — automatically moves the EAC failure popup off-screen.
//
// Detection strategy (v3):
//   The "EAC Failure" popup in AoC is rendered by UE5 Slate, NOT a standard
//   Win32 dialog.  Its window class is "UnrealWindow", the same class used by
//   the main game window.  We distinguish the popup from the game window by:
//
//     1. "#32770" windows (standard Win32 dialog/MessageBox) owned by the AoC
//        process — always move these.
//     2. "UnrealWindow" windows owned by the AoC process that are SMALL
//        (width < 900 px) — these are secondary Slate windows (popup/dialog),
//        not the main game viewport.
//     3. Any window owned by the AoC process whose title contains EAC keywords
//        — belt-and-suspenders for window classes we haven't seen yet.
//
//   All matching windows are moved to (-32000, -32000) immediately.
//   WM_CLOSE is sent 3 s later to unblock the game thread.
//   If the game exits after WM_CLOSE: the EAC code calls RequestExit()
//   unconditionally — remove the WM_CLOSE call below and just leave the window
//   moved off-screen permanently.
//
// Compile (one-time):
//   csc /target:winexe /out:eac_popup_mover.exe ..\..\..\src\eac_popup_mover.cs
// Or build_server.ps1 does it automatically.
//
// Usage:
//   start "" /min eac_popup_mover.exe       (before launching the game)

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

class EacPopupMover
{
    // ── WinAPI ────────────────────────────────────────────────────────────
    delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [DllImport("user32.dll")] static extern bool EnumWindows(EnumWindowsProc fn, IntPtr lp);
    [DllImport("user32.dll")] static extern int  GetWindowText(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll")] static extern int  GetClassName(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] static extern bool SetWindowPos(IntPtr h, IntPtr ins, int x, int y, int cx, int cy, uint f);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
    [DllImport("user32.dll")] static extern bool GetWindowRect(IntPtr h, out RECT r);
    [DllImport("user32.dll")] static extern bool PostMessage(IntPtr h, uint msg, IntPtr wParam, IntPtr lParam);

    const uint SWP_NOSIZE         = 0x0001;
    const uint SWP_NOZORDER       = 0x0004;
    const uint SWP_NOACTIVATE     = 0x0010;
    const uint SWP_NOSENDCHANGING = 0x0400;
    const int  OFFSCREEN_X        = -32000;
    const int  OFFSCREEN_Y        = -32000;
    const uint WM_CLOSE           = 0x0010;

    // Any window narrower than this (in pixels) is considered a dialog,
    // not the full-screen game viewport.
    const int  MAX_DIALOG_WIDTH   = 900;

    // Window classes we recognise
    const string CLASS_WIN32_DIALOG = "#32770";          // standard MessageBox / DialogBox
    const string CLASS_UE5_SLATE    = "UnrealWindow";    // UE5 Slate window (game + popups)
    const string CLASS_UE4_SLATE    = "UnrealWindowClass"; // older UE builds

    // Title-substring patterns — catch anything EAC-related regardless of class
    static readonly string[] TitlePatterns = {
        "EAC", "Easy Anti-Cheat", "AntiCheat", "Anti-Cheat",
        "EAC Failure", "EasyAntiCheat", "Failure"
    };

    // AoC process name (no .exe)
    const string AOC_PROCESS = "AOCClient-Win64-Shipping";

    [StructLayout(LayoutKind.Sequential)]
    struct RECT { public int Left, Top, Right, Bottom; }

    static int  s_moved   = 0;
    static bool s_running = true;

    // Dialogs queued for WM_CLOSE (hwnd → time moved)
    static readonly Dictionary<IntPtr, DateTime> s_pending =
        new Dictionary<IntPtr, DateTime>();

    // All AoC windows we have already logged (to avoid noisy repeat prints)
    static readonly HashSet<IntPtr> s_seenWindows = new HashSet<IntPtr>();

    static void Main(string[] args)
    {
        Console.WriteLine("[EacMover] Started (v3 — #32770 + UnrealWindow + title fallback)");
        Console.WriteLine("[EacMover] Watching for AOCClient-Win64-Shipping.exe popups...");
        Console.WriteLine("[EacMover] Matching: class=#32770, small UnrealWindow (<900px), or EAC title.");

        AppDomain.CurrentDomain.ProcessExit += (s, e) => s_running = false;
        Console.CancelKeyPress += (s, e) => { s_running = false; e.Cancel = false; };

        while (s_running)
        {
            try
            {
                ScanWindows();
                TryAutoClose();

                if (Process.GetProcessesByName(AOC_PROCESS).Length == 0 && s_moved > 0)
                {
                    Console.WriteLine("[EacMover] AoC process exited — stopping.");
                    break;
                }
            }
            catch (Exception ex) { Console.WriteLine("[EacMover] Exception: " + ex.Message); }
            Thread.Sleep(200);
        }
        Console.WriteLine("[EacMover] Exiting.");
    }

    static void ScanWindows()
    {
        var aocProcs = Process.GetProcessesByName(AOC_PROCESS);
        if (aocProcs.Length == 0) return;

        var aocPids = new HashSet<uint>();
        foreach (var p in aocProcs) aocPids.Add((uint)p.Id);

        EnumWindows((hWnd, _) =>
        {
            if (!IsWindowVisible(hWnd)) return true;

            // Must belong to the AoC process
            uint ownerPid = 0;
            GetWindowThreadProcessId(hWnd, out ownerPid);
            if (!aocPids.Contains(ownerPid)) return true;

            // Collect window attributes
            var clsBuf = new StringBuilder(256);
            GetClassName(hWnd, clsBuf, 256);
            string cls = clsBuf.ToString();

            var titleBuf = new StringBuilder(512);
            GetWindowText(hWnd, titleBuf, 512);
            string title = string.IsNullOrEmpty(titleBuf.ToString()) ? "(no title)" : titleBuf.ToString();

            RECT r;
            GetWindowRect(hWnd, out r);
            int w = r.Right - r.Left;
            int h = r.Bottom - r.Top;

            // ── Diagnostic: log every new AoC window we see ──────────────
            if (s_seenWindows.Add(hWnd))
            {
                Console.WriteLine(string.Format(
                    "[EacMover] [new window] class=\"{0}\" title=\"{1}\" size={2}x{3} pid={4} hwnd=0x{5:X}",
                    cls, title, w, h, ownerPid, hWnd.ToInt64()));
            }

            // ── Match criteria ────────────────────────────────────────────
            bool match = false;
            string reason = "";

            if (string.Equals(cls, CLASS_WIN32_DIALOG, StringComparison.Ordinal))
            {
                match = true; reason = "class=#32770";
            }
            else if ((string.Equals(cls, CLASS_UE5_SLATE,  StringComparison.Ordinal) ||
                      string.Equals(cls, CLASS_UE4_SLATE,  StringComparison.Ordinal))
                     && w > 0 && w < MAX_DIALOG_WIDTH)
            {
                match = true; reason = string.Format("UnrealWindow size={0}x{1} (<{2}px wide)", w, h, MAX_DIALOG_WIDTH);
            }
            else
            {
                // Title-pattern fallback (any class)
                foreach (var pat in TitlePatterns)
                {
                    if (title.IndexOf(pat, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        match = true; reason = "title contains \"" + pat + "\"";
                        break;
                    }
                }
            }

            if (!match) return true;

            // Already off-screen? Skip.
            if (r.Left <= OFFSCREEN_X + 100 && r.Top <= OFFSCREEN_Y + 100)
                return true;

            // Move off-screen
            bool ok = SetWindowPos(hWnd, IntPtr.Zero,
                OFFSCREEN_X, OFFSCREEN_Y, 0, 0,
                SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_NOSENDCHANGING);

            int n = Interlocked.Increment(ref s_moved);
            Console.WriteLine(string.Format(
                "[EacMover] #{0} Moved window off-screen  reason=\"{1}\"",
                n, reason));
            Console.WriteLine(string.Format(
                "           class=\"{0}\" title=\"{1}\" size={2}x{3} pid={4} hwnd=0x{5:X} ok={6}",
                cls, title, w, h, ownerPid, hWnd.ToInt64(), ok));
            Console.WriteLine("[EacMover]   Will send WM_CLOSE in 3s to unblock game thread.");
            Console.WriteLine("[EacMover]   If game EXITS: remove TryAutoClose() call — leave window moved.");
            Console.WriteLine("[EacMover]   If game SURVIVES: EAC thread unblocked — replay should resume.");

            lock (s_pending) s_pending[hWnd] = DateTime.Now;
            return true;
        }, IntPtr.Zero);
    }

    static void TryAutoClose()
    {
        var toClose = new List<IntPtr>();
        lock (s_pending)
        {
            foreach (var kv in s_pending)
                if ((DateTime.Now - kv.Value).TotalSeconds >= 3.0)
                    toClose.Add(kv.Key);
            foreach (var h in toClose) s_pending.Remove(h);
        }
        foreach (var hWnd in toClose)
        {
            if (!IsWindowVisible(hWnd)) continue;
            bool sent = PostMessage(hWnd, WM_CLOSE, IntPtr.Zero, IntPtr.Zero);
            Console.WriteLine(string.Format(
                "[EacMover] Sent WM_CLOSE to hwnd=0x{0:X} sent={1}",
                hWnd.ToInt64(), sent));
        }
    }
}

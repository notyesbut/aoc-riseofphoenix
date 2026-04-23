// ===========================================================================
//  launcher_main.cpp  –  AoC Emulator Launcher  (v3 – multi-version)
//
//  Win32 GUI.  No gRPC/protobuf — WinInet + nlohmann_json only.
//
//  Layout (client 540 × 540):
//    [  0 –  64]  Header strip  – title + red underline
//    [ 64 – 178]  Banner        – big title + subtitle
//    [178 – 248]  Version bar   – ORIGINAL | PROD | PTR tab buttons
//    [248 – 416]  Form          – username/password, login/register, feedback
//    [416 – 462]  Status bar
//    [462 – 540]  Bottom bar    – LAUNCH GAME button + version label
// ===========================================================================
#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <windows.h>
#include <windowsx.h>
#include <wininet.h>
#include <commctrl.h>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "comctl32.lib")

#include <nlohmann/json.hpp>

#include <atomic>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <array>

using json = nlohmann::json;

// ===========================================================================
//  Palette
// ===========================================================================
static const COLORREF kBg       = RGB( 10,  10,  18);
static const COLORREF kHeader   = RGB( 16,  16,  30);
static const COLORREF kVerBar   = RGB( 13,  13,  24);
static const COLORREF kStatus   = RGB( 20,  20,  36);
static const COLORREF kBottom   = RGB( 14,  14,  26);
static const COLORREF kSep      = RGB( 38,  38,  60);
static const COLORREF kAccent   = RGB(190,  28,  28);
static const COLORREF kAccentHv = RGB(220,  50,  50);
static const COLORREF kAccentPs = RGB(155,  18,  18);
static const COLORREF kAccentDs = RGB( 60,  18,  18);
static const COLORREF kBtnDark  = RGB( 28,  28,  46);
static const COLORREF kBtnDkHv  = RGB( 44,  44,  68);
static const COLORREF kTabSel   = RGB( 24,   8,   8);   // selected-tab bg
static const COLORREF kField    = RGB( 22,  22,  38);
static const COLORREF kTxtWht   = RGB(240, 240, 255);
static const COLORREF kTxtSub   = RGB(155, 155, 180);
static const COLORREF kTxtDim   = RGB( 85,  85, 108);
static const COLORREF kTxtOk    = RGB(110, 220, 140);
static const COLORREF kTxtErr   = RGB(235,  90,  90);

// ===========================================================================
//  Layout constants
// ===========================================================================
constexpr int kW = 540;
constexpr int kH = 540;

constexpr int kHeaderY = 0,   kHeaderH = 64;
constexpr int kBannerY = 64,  kBannerH = 114;
constexpr int kVerY    = 178, kVerH    = 70;
constexpr int kFormY   = 248, kFormH   = 168;
constexpr int kStatY   = 416, kStatH   = 46;
constexpr int kBotY    = 462, kBotH    = 78;

// Form fields
constexpr int kFldX = 128, kFldW = 294, kFldH = 28, kFldGap = 14;
constexpr int kF1Y  = kFormY + 14;
constexpr int kF2Y  = kF1Y + kFldH + kFldGap;
constexpr int kLblW = 112;

// Version tabs
constexpr int kTabW = kW / 3;   // 180 px each

// ===========================================================================
//  Control IDs
// ===========================================================================
enum {
    ID_USER    = 101,
    ID_PASS    = 102,
    ID_LOGIN   = 103,
    ID_REG     = 104,
    ID_LAUNCH  = 105,
    ID_VER0    = 110,   // ORIGINAL
    ID_VER1    = 111,   // PROD
    ID_VER2    = 112,   // PTR
};

// ===========================================================================
//  Version info
// ===========================================================================
enum Version { VER_ORIG = 0, VER_PROD = 1, VER_PTR = 2 };

struct VerInfo {
    const wchar_t* label;       // tab title
    const wchar_t* sublabel;    // small description shown in tab
    const char*    json_key;    // key in paths.json
    const char*    fallback;    // hardcoded default path
};

static const std::array<VerInfo, 3> kVersions = {{
    // Launch the Shipping binary directly (not the EAC bootstrapper AOCClient.exe).
    // With EOS_USE_ANTICHEATCLIENTNULL=1 inherited by the child, the EOS SDK's
    // null anti-cheat stub is activated — no real EAC server contact, no popup.
    { L"ORIGINAL",  L"Retail Steam build",
      "game_executable",
      "C:\\Ashes of Creation\\Game\\AOC\\Binaries\\Win64\\AOCClient-Win64-Shipping.exe" },
    { L"PROD",      L"Pre-Steam / Alpha build",
      "game_executable_prod",
      "E:\\AshesOfCreation\\PROD\\AOC\\Binaries\\Win64\\AOCClient-Win64-Shipping.exe" },
    { L"PTR",       L"Public Test Realm",
      "game_executable_ptr",
      "E:\\AshesOfCreation\\PTR\\AOC\\Binaries\\Win64\\AOCClient-Win64-Shipping.exe" },
}};

// ===========================================================================
//  GDI resources
// ===========================================================================
static HBRUSH g_brBg     = nullptr;
static HBRUSH g_brField  = nullptr;
static HBRUSH g_brBottom = nullptr;
static HFONT  g_fntBig   = nullptr;
static HFONT  g_fntMed   = nullptr;
static HFONT  g_fntForm  = nullptr;
static HFONT  g_fntSmall = nullptr;
static HFONT  g_fntTab   = nullptr;   // bold tab label

// ===========================================================================
//  Application state
// ===========================================================================
static bool         g_loggedIn   = false;
static std::wstring g_username;
static std::wstring g_feedback;
static bool         g_feedbackErr = false;
static Version      g_selVer     = VER_ORIG;

// Hover flags
static bool g_hoverLogin  = false;
static bool g_hoverReg    = false;
static bool g_hoverLaunch = false;
static int  g_hoverTab    = -1;   // which tab is hovered (-1 = none)

static std::atomic<bool> g_authBusy{false};
constexpr UINT WM_AUTH_DONE = WM_APP + 1;
struct AuthResult { bool ok; std::string message; };

static HWND g_hwnd = nullptr;

// ===========================================================================
//  Config helpers
// ===========================================================================
static std::string exe_dir()
{
    char buf[MAX_PATH]{};
    ::GetModuleFileNameA(nullptr, buf, MAX_PATH);
    std::string s(buf);
    auto p = s.find_last_of("\\/");
    return (p != std::string::npos) ? s.substr(0, p + 1) : "";
}

static std::string json_str(const std::string& path, const std::string& key,
                             const std::string& def = "")
{
    try {
        std::ifstream f(path); if (!f) return def;
        return json::parse(f).value(key, def);
    } catch (...) { return def; }
}

static int json_int(const std::string& path, const std::string& key, int def)
{
    try {
        std::ifstream f(path); if (!f) return def;
        return json::parse(f).value(key, def);
    } catch (...) { return def; }
}

// Returns the exe path for the currently selected version
static std::string selected_exe()
{
    const auto& v = kVersions[g_selVer];
    const std::string dir = exe_dir();
    return json_str(dir + "config\\paths.json", v.json_key, v.fallback);
}

// ===========================================================================
//  HTTP POST (WinInet)
// ===========================================================================
static std::string http_post(const std::string& host, int port,
                              const std::string& path, const std::string& body)
{
    HINTERNET hI = InternetOpenA("AoCEmu/3.0", INTERNET_OPEN_TYPE_DIRECT,
                                 nullptr, nullptr, 0);
    if (!hI) return "";
    HINTERNET hC = InternetConnectA(hI, host.c_str(), (INTERNET_PORT)port,
                                    nullptr, nullptr, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hC) { InternetCloseHandle(hI); return ""; }
    HINTERNET hR = HttpOpenRequestA(hC, "POST", path.c_str(), nullptr, nullptr,
                                    nullptr, INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hR) { InternetCloseHandle(hC); InternetCloseHandle(hI); return ""; }

    const char* hdrs = "Content-Type: application/json\r\n";
    std::string result;
    if (HttpSendRequestA(hR, hdrs, (DWORD)strlen(hdrs),
                         const_cast<char*>(body.c_str()), (DWORD)body.size())) {
        char buf[4096]; DWORD n;
        while (InternetReadFile(hR, buf, sizeof(buf)-1, &n) && n)
        { buf[n] = 0; result += buf; }
    }
    InternetCloseHandle(hR); InternetCloseHandle(hC); InternetCloseHandle(hI);
    return result;
}

// ===========================================================================
//  Game launcher
// ===========================================================================
static std::string launch_game()
{
    const std::string exe = selected_exe();
    if (exe.empty())
        return "No executable configured for this version.";
    if (!std::filesystem::exists(exe))
        return "Executable not found:\n" + exe;

    const std::string dir = exe_dir();
    const int tport = json_int(dir + "config\\server.json", "tether_port", 19021);
    const std::string extra = json_str(dir + "config\\server.json", "client_extra_args", "");

    std::string cmd = "\"" + exe + "\" -LauncherTetherPort=" + std::to_string(tport);
    if (!extra.empty()) cmd += ' ' + extra;

    // Use the exe's own directory as working directory.
    // (Previously the bootstrapper needed the game root for EasyAntiCheat/Settings.json,
    // but we now launch the Shipping binary directly so any dir inside the tree is fine.)
    std::string wd = exe;
    { auto p = wd.find_last_of("\\/"); if (p != std::string::npos) wd.resize(p+1); }

    // ── EAC bypass ───────────────────────────────────────────────────────────
    // Set EOS null anti-cheat env-vars in THIS process so they are inherited
    // by the EAC bootstrapper (AOCClient.exe) and then by the game binary.
    // Without these the EAC module inside the game tries to contact Epic's
    // real EAC auth servers and fails with "EAC Failure: Failed login, errno:32".
    ::SetEnvironmentVariableA("EOS_USE_ANTICHEATCLIENTNULL", "1");
    ::SetEnvironmentVariableA("EOS_ANTICHEAT_BOOTSTRAPPER_IMMEDIATE_EXIT_ON_ERROR", "0");

    STARTUPINFOA si{}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!::CreateProcessA(exe.c_str(), cmd.data(), nullptr, nullptr,
                          FALSE, 0, nullptr,
                          wd.empty() ? nullptr : wd.c_str(), &si, &pi))
        return "CreateProcess failed (error " + std::to_string(::GetLastError()) + ")";

    ::CloseHandle(pi.hProcess);
    ::CloseHandle(pi.hThread);
    return "";
}

// ===========================================================================
//  Auth worker
// ===========================================================================
static void auth_worker(HWND hwnd, std::string user, std::string pass, bool is_reg)
{
    const std::string dir = exe_dir();
    const std::string host = json_str(dir+"config\\server.json","auth_server_host","127.0.0.1");
    const int port = json_int(dir+"config\\server.json","auth_server_port",8081);
    const std::string ep = is_reg ? "/api/v1/auth/register" : "/api/v1/auth/login";

    json bj; bj["username"] = user; bj["password"] = pass;
    const std::string resp = http_post(host, port, ep, bj.dump());

    auto* r = new AuthResult{};
    if (resp.empty()) {
        r->ok = false;
        r->message = "Cannot reach auth_server at " + host + ":" +
                     std::to_string(port) + ". Is it running?";
    } else {
        try {
            auto j = json::parse(resp);
            if (j.contains("access_token")) {
                r->ok = true;
                r->message = is_reg ? "Registered + signed in as " + user
                                    : "Signed in as " + user;
            } else {
                r->ok = false;
                r->message = j.value("message", j.value("error", "Login failed."));
            }
        } catch (...) {
            r->ok = false;
            r->message = "Unexpected response from auth_server.";
        }
    }
    ::PostMessageW(hwnd, WM_AUTH_DONE, 0, (LPARAM)r);
    g_authBusy.store(false);
}

// ===========================================================================
//  Wide/UTF-8 conversion helpers
// ===========================================================================
static std::wstring to_wide(const std::string& s)
{
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, w.data(), n);
    if (!w.empty() && w.back() == L'\0') w.pop_back();
    return w;
}

static std::string to_utf8(const wchar_t* w)
{
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    std::string s(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, s.data(), n, nullptr, nullptr);
    if (!s.empty() && s.back() == '\0') s.pop_back();
    return s;
}

// ===========================================================================
//  GDI helpers
// ===========================================================================
static void fill_rect(HDC dc, int x, int y, int w, int h, COLORREF c)
{
    RECT r{ x, y, x+w, y+h };
    HBRUSH br = CreateSolidBrush(c);
    FillRect(dc, &r, br);
    DeleteObject(br);
}

static void draw_text_ex(HDC dc, const wchar_t* txt, int x, int y, int w, int h,
                          HFONT fnt, COLORREF col, UINT flags)
{
    RECT r{ x, y, x+w, y+h };
    SelectObject(dc, fnt);
    SetTextColor(dc, col);
    SetBkMode(dc, TRANSPARENT);
    DrawTextW(dc, txt, -1, &r, flags);
}

static void draw_btn(HDC dc, RECT r, const wchar_t* txt, HFONT fnt,
                     bool hover, bool pressed, bool enabled,
                     COLORREF base, COLORREF hv, COLORREF ps, COLORREF ds)
{
    COLORREF bg = !enabled ? ds : pressed ? ps : hover ? hv : base;
    HBRUSH br = CreateSolidBrush(bg);
    FillRect(dc, &r, br);
    DeleteObject(br);
    SelectObject(dc, fnt);
    SetTextColor(dc, enabled ? kTxtWht : kTxtDim);
    SetBkMode(dc, TRANSPARENT);
    DrawTextW(dc, txt, -1, &r, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
}

// Draw the version tab strip (in WM_PAINT, not owner-draw)
static void draw_version_bar(HDC dc)
{
    fill_rect(dc, 0, kVerY, kW, kVerH, kVerBar);
    fill_rect(dc, 0, kVerY, kW, 1, kSep);
    fill_rect(dc, 0, kVerY + kVerH - 1, kW, 1, kSep);

    for (int i = 0; i < 3; ++i) {
        const int tx = i * kTabW;
        const bool sel = (g_selVer == i);
        const bool hov = (g_hoverTab == i);

        // Tab background
        COLORREF bg = sel  ? kTabSel
                    : hov  ? kBtnDkHv
                           : kVerBar;
        fill_rect(dc, tx, kVerY, kTabW, kVerH, bg);

        // Left divider (except first tab)
        if (i > 0)
            fill_rect(dc, tx, kVerY + 8, 1, kVerH - 16, kSep);

        // Red bottom bar for selected
        if (sel)
            fill_rect(dc, tx + 1, kVerY + kVerH - 3, kTabW - 2, 3, kAccent);

        // Label
        COLORREF lblCol = sel ? kTxtWht : hov ? kTxtSub : kTxtDim;
        draw_text_ex(dc, kVersions[i].label,
                     tx, kVerY + 6, kTabW, 28,
                     g_fntTab, lblCol, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

        // Sub-label
        draw_text_ex(dc, kVersions[i].sublabel,
                     tx + 4, kVerY + 34, kTabW - 8, 22,
                     g_fntSmall, sel ? kTxtSub : kTxtDim,
                     DT_CENTER | DT_VCENTER | DT_SINGLELINE);

        // Availability dot
        const std::string exe = json_str(
            exe_dir() + "config\\paths.json",
            kVersions[i].json_key,
            kVersions[i].fallback);
        const bool avail = std::filesystem::exists(exe);
        COLORREF dotC = avail ? RGB(46, 204, 113) : RGB(180, 60, 60);
        HBRUSH br = CreateSolidBrush(dotC);
        HPEN   pn = CreatePen(PS_SOLID, 1, dotC);
        HBRUSH ob = (HBRUSH)SelectObject(dc, br);
        HPEN   op = (HPEN)SelectObject(dc, pn);
        const int cx = tx + kTabW - 14, cy = kVerY + 14;
        Ellipse(dc, cx-5, cy-5, cx+5, cy+5);
        SelectObject(dc, ob); SelectObject(dc, op);
        DeleteObject(br); DeleteObject(pn);
    }
}

// ===========================================================================
//  WM_PAINT
// ===========================================================================
static void on_paint(HWND hwnd)
{
    PAINTSTRUCT ps;
    HDC dc = BeginPaint(hwnd, &ps);

    // ── Header ──────────────────────────────────────────────────────────────
    fill_rect(dc, 0, kHeaderY, kW, kHeaderH, kHeader);
    fill_rect(dc, 0, kHeaderY + kHeaderH - 2, kW, 2, kAccent);
    draw_text_ex(dc, L"ASHES OF CREATION  \u00b7  EMULATOR",
                 20, kHeaderY, kW - 40, kHeaderH,
                 g_fntMed, kTxtWht, DT_LEFT | DT_VCENTER | DT_SINGLELINE);

    // ── Banner ───────────────────────────────────────────────────────────────
    fill_rect(dc, 0, kBannerY, kW, kBannerH, kBg);
    draw_text_ex(dc, L"ASHES OF CREATION",
                 0, kBannerY + 10, kW, 60,
                 g_fntBig, kTxtWht, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    draw_text_ex(dc, L"Emulator Build  \u00b7  Pre-Alpha  \u00b7  v 0.1.0",
                 0, kBannerY + 76, kW, 28,
                 g_fntSmall, kTxtSub, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

    // ── Version selector ─────────────────────────────────────────────────────
    draw_version_bar(dc);

    // ── Form background ──────────────────────────────────────────────────────
    fill_rect(dc, 0, kFormY, kW, kFormH, kBg);

    if (!g_loggedIn) {
        draw_text_ex(dc, L"Username",
                     kFldX - kLblW - 8, kF1Y, kLblW, kFldH,
                     g_fntSmall, kTxtSub, DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
        draw_text_ex(dc, L"Password",
                     kFldX - kLblW - 8, kF2Y, kLblW, kFldH,
                     g_fntSmall, kTxtSub, DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
    } else {
        std::wstring msg = L"Logged in as  " + g_username;
        draw_text_ex(dc, msg.c_str(),
                     0, kFormY + 26, kW, 36,
                     g_fntMed, kTxtWht, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    }

    // Feedback line
    if (!g_feedback.empty()) {
        int fbY = g_loggedIn ? kFormY + 78 : kFormY + kFormH - 34;
        draw_text_ex(dc, g_feedback.c_str(),
                     20, fbY, kW - 40, 26,
                     g_fntSmall, g_feedbackErr ? kTxtErr : kTxtOk,
                     DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    }

    // ── Status bar ───────────────────────────────────────────────────────────
    fill_rect(dc, 0, kStatY, kW, kStatH, kStatus);
    fill_rect(dc, 0, kStatY, kW, 1, kSep);

    // Show which exe will be launched
    std::string exePath = selected_exe();
    bool exeOk = !exePath.empty() && std::filesystem::exists(exePath);
    std::wstring statMsg = exeOk
        ? L"\u2713  " + to_wide(exePath)
        : L"\u26a0  Not found: " + to_wide(exePath);
    draw_text_ex(dc, statMsg.c_str(),
                 12, kStatY, kW - 24, kStatH,
                 g_fntSmall, exeOk ? kTxtSub : kTxtErr,
                 DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);

    // ── Bottom bar ────────────────────────────────────────────────────────────
    fill_rect(dc, 0, kBotY, kW, kBotH, kBottom);
    fill_rect(dc, 0, kBotY, kW, 1, kSep);
    draw_text_ex(dc, L"v 0.1.0",
                 16, kBotY, 120, kBotH,
                 g_fntSmall, kTxtDim, DT_LEFT | DT_VCENTER | DT_SINGLELINE);

    EndPaint(hwnd, &ps);
}

// ===========================================================================
//  WM_DRAWITEM  (owner-draw buttons only: Login, Register, Launch)
// ===========================================================================
static void on_draw_item(DRAWITEMSTRUCT* dis)
{
    const bool pressed = (dis->itemState & ODS_SELECTED) != 0;
    const bool enabled = (dis->itemState & ODS_DISABLED) == 0;
    RECT r = dis->rcItem;

    switch (dis->CtlID) {
    case ID_LOGIN:
        draw_btn(dis->hDC, r, L"Login", g_fntForm,
                 g_hoverLogin, pressed, enabled,
                 kAccent, kAccentHv, kAccentPs, kAccentDs);
        break;
    case ID_REG:
        draw_btn(dis->hDC, r, L"Register", g_fntForm,
                 g_hoverReg, pressed, enabled,
                 kBtnDark, kBtnDkHv, kBtnDark, kBtnDark);
        {   // Subtle border
            HPEN pen = CreatePen(PS_SOLID, 1, kSep);
            HPEN op  = (HPEN)SelectObject(dis->hDC, pen);
            HBRUSH nb = (HBRUSH)GetStockObject(NULL_BRUSH);
            HBRUSH ob = (HBRUSH)SelectObject(dis->hDC, nb);
            Rectangle(dis->hDC, r.left, r.top, r.right, r.bottom);
            SelectObject(dis->hDC, op); SelectObject(dis->hDC, ob);
            DeleteObject(pen);
        }
        break;
    case ID_LAUNCH:
        draw_btn(dis->hDC, r, L"LAUNCH GAME", g_fntMed,
                 g_hoverLaunch, pressed, enabled,
                 kAccent, kAccentHv, kAccentPs, kAccentDs);
        break;
    }
}

// ===========================================================================
//  Sync control visibility / enable state
// ===========================================================================
static void sync_controls(HWND hwnd)
{
    const bool lo = g_loggedIn;
    ShowWindow(GetDlgItem(hwnd, ID_USER),  lo ? SW_HIDE : SW_SHOW);
    ShowWindow(GetDlgItem(hwnd, ID_PASS),  lo ? SW_HIDE : SW_SHOW);
    ShowWindow(GetDlgItem(hwnd, ID_LOGIN), lo ? SW_HIDE : SW_SHOW);
    ShowWindow(GetDlgItem(hwnd, ID_REG),   lo ? SW_HIDE : SW_SHOW);

    // Launch is enabled only when logged in AND exe exists
    const bool canLaunch = lo && std::filesystem::exists(selected_exe());
    EnableWindow(GetDlgItem(hwnd, ID_LAUNCH), canLaunch);

    InvalidateRect(hwnd, nullptr, FALSE);
}

// Hit-test which tab (0/1/2) a point is in, or -1
static int hit_tab(int mx, int my)
{
    if (my < kVerY || my >= kVerY + kVerH) return -1;
    if (mx < 0 || mx >= kW) return -1;
    return mx / kTabW;
}

// ===========================================================================
//  Window procedure
// ===========================================================================
static LRESULT CALLBACK wnd_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg)
    {
    case WM_CREATE:
    {
        g_hwnd = hwnd;
        HINSTANCE hi = GetModuleHandleW(nullptr);

        // Username / password
        HWND hU = CreateWindowExW(0, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
            kFldX, kF1Y, kFldW, kFldH,
            hwnd, (HMENU)(INT_PTR)ID_USER, hi, nullptr);
        SendMessageW(hU, EM_SETLIMITTEXT, 64, 0);

        HWND hP = CreateWindowExW(0, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | ES_PASSWORD,
            kFldX, kF2Y, kFldW, kFldH,
            hwnd, (HMENU)(INT_PTR)ID_PASS, hi, nullptr);
        SendMessageW(hP, EM_SETLIMITTEXT, 128, 0);

        // Login + Register buttons
        const int btnY = kF2Y + kFldH + 20;
        const int btnW = (kFldW - 12) / 2;
        const int btnH = 36;
        CreateWindowW(L"BUTTON", L"Login",
            WS_CHILD | WS_VISIBLE | BS_OWNERDRAW | BS_DEFPUSHBUTTON,
            kFldX, btnY, btnW, btnH,
            hwnd, (HMENU)(INT_PTR)ID_LOGIN, hi, nullptr);
        CreateWindowW(L"BUTTON", L"Register",
            WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
            kFldX + btnW + 12, btnY, btnW, btnH,
            hwnd, (HMENU)(INT_PTR)ID_REG, hi, nullptr);

        // LAUNCH GAME button
        const int launchW = 280, launchH = 42;
        CreateWindowW(L"BUTTON", L"LAUNCH GAME",
            WS_CHILD | WS_VISIBLE | BS_OWNERDRAW | WS_DISABLED,
            (kW - launchW) / 2, kBotY + (kBotH - launchH) / 2,
            launchW, launchH,
            hwnd, (HMENU)(INT_PTR)ID_LAUNCH, hi, nullptr);

        // Fonts
        SendMessageW(hU, WM_SETFONT, (WPARAM)g_fntForm, TRUE);
        SendMessageW(hP, WM_SETFONT, (WPARAM)g_fntForm, TRUE);

        sync_controls(hwnd);
        return 0;
    }

    case WM_PAINT:
        on_paint(hwnd);
        return 0;

    case WM_ERASEBKGND:
        return 1;

    case WM_CTLCOLOREDIT:
    {
        HDC dc = (HDC)wp;
        SetTextColor(dc, kTxtWht);
        SetBkColor(dc, kField);
        return (LRESULT)g_brField;
    }
    case WM_CTLCOLORSTATIC:
    {
        HDC dc = (HDC)wp;
        SetTextColor(dc, kTxtSub);
        SetBkColor(dc, kBg);
        return (LRESULT)g_brBg;
    }
    case WM_CTLCOLORBTN:
        return (LRESULT)g_brBg;

    case WM_DRAWITEM:
        on_draw_item((DRAWITEMSTRUCT*)lp);
        return TRUE;

    case WM_MOUSEMOVE:
    {
        const int mx = LOWORD(lp), my = (SHORT)HIWORD(lp);
        HWND hit = ChildWindowFromPoint(hwnd, {mx, my});

        auto refresh_btn = [&](HWND h, bool& flag, bool want) {
            if (flag != want) { flag = want; if (h) InvalidateRect(h, nullptr, FALSE); }
        };
        refresh_btn(GetDlgItem(hwnd, ID_LOGIN),  g_hoverLogin,  hit == GetDlgItem(hwnd, ID_LOGIN));
        refresh_btn(GetDlgItem(hwnd, ID_REG),    g_hoverReg,    hit == GetDlgItem(hwnd, ID_REG));
        refresh_btn(GetDlgItem(hwnd, ID_LAUNCH), g_hoverLaunch, hit == GetDlgItem(hwnd, ID_LAUNCH));

        // Version tab hover
        const int ht = hit_tab(mx, my);
        if (ht != g_hoverTab) {
            g_hoverTab = ht;
            // Invalidate just the version bar
            RECT vr{ 0, kVerY, kW, kVerY + kVerH };
            InvalidateRect(hwnd, &vr, FALSE);
        }
        return 0;
    }

    case WM_MOUSELEAVE:
        g_hoverLogin = g_hoverReg = g_hoverLaunch = false;
        g_hoverTab = -1;
        InvalidateRect(hwnd, nullptr, FALSE);
        return 0;

    case WM_LBUTTONDOWN:
    {
        const int mx = LOWORD(lp), my = (SHORT)HIWORD(lp);
        const int tab = hit_tab(mx, my);
        if (tab >= 0 && tab != (int)g_selVer) {
            g_selVer = (Version)tab;
            sync_controls(hwnd);   // re-evaluate launch button + repaint
        }
        return 0;
    }

    case WM_AUTH_DONE:
    {
        auto* r = (AuthResult*)lp;
        if (r->ok) {
            g_loggedIn = true;
            g_username = to_wide(r->message);
            g_feedback.clear();
        } else {
            g_feedbackErr = true;
            g_feedback = to_wide(r->message);
        }
        delete r;
        sync_controls(hwnd);
        return 0;
    }

    case WM_COMMAND:
    {
        const int id = LOWORD(wp);

        if ((id == ID_LOGIN || id == ID_REG) && !g_authBusy.exchange(true)) {
            wchar_t wu[128]{}, wp2[128]{};
            GetDlgItemTextW(hwnd, ID_USER, wu, 128);
            GetDlgItemTextW(hwnd, ID_PASS, wp2, 128);
            std::string user = to_utf8(wu), pass = to_utf8(wp2);

            if (user.empty() || pass.empty()) {
                g_feedback = L"Username and password are required.";
                g_feedbackErr = true;
                g_authBusy.store(false);
                InvalidateRect(hwnd, nullptr, FALSE);
                break;
            }

            g_feedback = L"Contacting auth server\u2026";
            g_feedbackErr = false;
            InvalidateRect(hwnd, nullptr, FALSE);

            const bool is_reg = (id == ID_REG);
            std::thread([hwnd, user, pass, is_reg]{
                auth_worker(hwnd, user, pass, is_reg);
            }).detach();
        }

        if (id == ID_LAUNCH && g_loggedIn) {
            EnableWindow(GetDlgItem(hwnd, ID_LAUNCH), FALSE);
            g_feedback = L"Launching game\u2026";
            g_feedbackErr = false;
            InvalidateRect(hwnd, nullptr, FALSE);
            UpdateWindow(hwnd);

            std::string err = launch_game();
            if (err.empty()) {
                g_feedback = L"Game launched.  (";
                g_feedback += kVersions[g_selVer].label;
                g_feedback += L")";
                g_feedbackErr = false;
            } else {
                EnableWindow(GetDlgItem(hwnd, ID_LAUNCH), TRUE);
                g_feedback = to_wide(err);
                g_feedbackErr = true;
                MessageBoxA(hwnd, err.c_str(), "Launch failed", MB_OK | MB_ICONERROR);
            }
            InvalidateRect(hwnd, nullptr, FALSE);
        }
        return 0;
    }

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

// ===========================================================================
//  Entry point
// ===========================================================================
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE, LPSTR, int)
{
    INITCOMMONCONTROLSEX icc{ sizeof(icc), ICC_STANDARD_CLASSES };
    InitCommonControlsEx(&icc);

    g_brBg     = CreateSolidBrush(kBg);
    g_brField  = CreateSolidBrush(kField);
    g_brBottom = CreateSolidBrush(kBottom);

    g_fntBig = CreateFontW(48, 0, 0, 0, FW_BLACK,    FALSE, FALSE, FALSE,
                           DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                           CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
    g_fntMed = CreateFontW(17, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                           DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                           CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
    g_fntTab = CreateFontW(15, 0, 0, 0, FW_BOLD,     FALSE, FALSE, FALSE,
                           DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                           CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
    g_fntForm = CreateFontW(15, 0, 0, 0, FW_NORMAL,  FALSE, FALSE, FALSE,
                            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                            CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
    g_fntSmall = CreateFontW(12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                             DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                             CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");

    WNDCLASSW wc{};
    wc.lpfnWndProc   = wnd_proc;
    wc.hInstance     = hInst;
    wc.lpszClassName = L"AocEmuLauncher3";
    wc.hbrBackground = g_brBg;
    wc.hCursor       = LoadCursorW(nullptr, (LPCWSTR)IDC_ARROW);
    wc.hIcon         = LoadIconW(nullptr, (LPCWSTR)IDI_APPLICATION);
    RegisterClassW(&wc);

    DWORD style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX;
    RECT wr{ 0, 0, kW, kH };
    AdjustWindowRectEx(&wr, style, FALSE, 0);
    const int ww = wr.right - wr.left, wh = wr.bottom - wr.top;
    const int sx = (GetSystemMetrics(SM_CXSCREEN) - ww) / 2;
    const int sy = (GetSystemMetrics(SM_CYSCREEN) - wh) / 2;

    HWND hwnd = CreateWindowExW(0,
        L"AocEmuLauncher3",
        L"Ashes of Creation \u2014 Emulator Launcher",
        style | WS_VISIBLE,
        sx, sy, ww, wh, nullptr, nullptr, hInst, nullptr);
    if (!hwnd) return 1;

    MSG m{};
    while (GetMessageW(&m, nullptr, 0, 0) > 0) {
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }

    DeleteObject(g_fntBig); DeleteObject(g_fntMed);
    DeleteObject(g_fntTab); DeleteObject(g_fntForm); DeleteObject(g_fntSmall);
    DeleteObject(g_brBg);   DeleteObject(g_brField); DeleteObject(g_brBottom);
    return (int)m.wParam;
}

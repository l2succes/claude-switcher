import AppKit
import SwiftUI
import CommonCrypto
import ServiceManagement

// Claude Switcher — menu bar app that swaps Claude Desktop's data folder between accounts
// and shows live plan usage for each one.
//
// Active profile lives at ~/Library/Application Support/Claude (a real dir).
// Inactive profiles are parked at ~/Library/Application Support/Claude-Profiles/<name>.
// Switching = quit Claude, rename dirs (instant, same volume), relaunch.
// Usage comes from each profile's own OAuth token (decrypted from its config.json).

let bundleID = "com.anthropic.claudefordesktop"
let fm = FileManager.default
let support = fm.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
let liveDir = support.appendingPathComponent("Claude")
let parkDir = support.appendingPathComponent("Claude-Profiles")
let currentFile = parkDir.appendingPathComponent(".current")
let cacheDir = parkDir.appendingPathComponent(".cache")
let defaultProfiles = ["Personal", "Business"]

// MARK: - Colors

extension Color {
    init(hex: UInt32, _ a: Double = 1) {
        self.init(.sRGB, red: Double((hex >> 16) & 0xff) / 255, green: Double((hex >> 8) & 0xff) / 255,
                  blue: Double(hex & 0xff) / 255, opacity: a)
    }
    static let bg = Color(hex: 0x1C1B19)
    static let card = Color(hex: 0x262522)
    static let cardHi = Color(hex: 0x2E2A26)
    static let stroke = Color(hex: 0x3A3833)
    static let txt = Color(hex: 0xF2EFE8)
    static let sub = Color(hex: 0x9C978C)
    static let claude = Color(hex: 0xD97757)
    static let good = Color(hex: 0x6CC57C)
    static let warn = Color(hex: 0xE5B454)
    static let bad = Color(hex: 0xE5675A)
}

func levelColor(_ left: Double?) -> Color {
    guard let l = left else { return .sub }
    return l > 50 ? .good : l > 20 ? .warn : .bad
}

// MARK: - Data

struct Window: Codable { var used: Double; var resetsAt: Date? }

struct Snapshot: Codable {
    var email: String?
    var name: String?
    var plan: String?
    var session: Window?
    var weekly: Window?
    var weeklyOpus: Window?
    var extraEnabled: Bool?
    var fetchedAt: Date
}

struct Profile: Identifiable {
    var id: String { name }
    let name: String
    var snapshot: Snapshot?
    var signedIn: Bool
    var error: String?
    var live: Bool { error == nil && snapshot.map { Date().timeIntervalSince($0.fetchedAt) < 600 } == true }
}

func currentProfile() -> String {
    (try? String(contentsOf: currentFile, encoding: .utf8))?
        .trimmingCharacters(in: .whitespacesAndNewlines) ?? defaultProfiles[0]
}

func profileDir(_ name: String) -> URL {
    name == currentProfile() ? liveDir : parkDir.appendingPathComponent(name)
}

func allProfileNames() -> [String] {
    let cur = currentProfile()
    let parked = ((try? fm.contentsOfDirectory(atPath: parkDir.path)) ?? [])
        .filter { !$0.hasPrefix(".") }
    var names = [cur] + parked.filter { $0 != cur }
    // stable order: defaults first, then alphabetical
    names.sort { a, b in
        let ia = defaultProfiles.firstIndex(of: a) ?? 99, ib = defaultProfiles.firstIndex(of: b) ?? 99
        return ia != ib ? ia < ib : a < b
    }
    return names
}

// MARK: - Token decryption (Electron safeStorage: "v10" + AES-128-CBC, PBKDF2-SHA1 "saltysalt")

var cachedSafeKey: Data?

func safeStorageKey() throws -> Data {
    if let k = cachedSafeKey { return k }
    let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                            kSecAttrService as String: "Claude Safe Storage",
                            kSecReturnData as String: true]
    var out: CFTypeRef?
    let st = SecItemCopyMatching(q as CFDictionary, &out)
    guard st == errSecSuccess, let pw = out as? Data else {
        throw err("Keychain access denied (\(st)). Allow access to \"Claude Safe Storage\".")
    }
    var key = Data(count: 16)
    let salt = Array("saltysalt".utf8)
    let rc = key.withUnsafeMutableBytes { kp in
        pw.withUnsafeBytes { pp in
            CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), pp.baseAddress!.assumingMemoryBound(to: Int8.self), pw.count,
                                 salt, salt.count, CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1), 1003,
                                 kp.baseAddress!.assumingMemoryBound(to: UInt8.self), 16)
        }
    }
    guard rc == kCCSuccess else { throw err("Key derivation failed") }
    cachedSafeKey = key
    return key
}

func decrypt(_ b64: String) throws -> Data {
    guard let raw = Data(base64Encoded: b64), raw.prefix(3) == Data("v10".utf8) else { throw err("Unknown token format") }
    let body = raw.dropFirst(3)
    let key = try safeStorageKey()
    let iv = [UInt8](repeating: 0x20, count: 16)
    var out = Data(count: body.count + 16)
    var moved = 0
    let outCap = out.count
    let rc = out.withUnsafeMutableBytes { op in
        body.withUnsafeBytes { bp in
            key.withUnsafeBytes { kp in
                CCCrypt(CCOperation(kCCDecrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionPKCS7Padding),
                        kp.baseAddress, 16, iv, bp.baseAddress, body.count, op.baseAddress, outCap, &moved)
            }
        }
    }
    guard rc == kCCSuccess else { throw err("Token decrypt failed") }
    return out.prefix(moved)
}

func err(_ s: String) -> NSError { NSError(domain: "switcher", code: 1, userInfo: [NSLocalizedDescriptionKey: s]) }

/// Best non-expired token with user:profile scope from a profile's config.json, or nil if signed out.
func token(for dir: URL) throws -> String? {
    guard let data = try? Data(contentsOf: dir.appendingPathComponent("config.json")),
          let cfg = try JSONSerialization.jsonObject(with: data) as? [String: Any],
          let enc = cfg["oauth:tokenCacheV2"] as? String else { return nil }
    let dict = try JSONSerialization.jsonObject(with: try decrypt(enc)) as? [String: [String: Any]] ?? [:]
    let now = Date().timeIntervalSince1970 * 1000
    return dict.filter { $0.key.contains("user:profile") }
        .compactMap { _, v -> (String, Double)? in
            guard let t = v["token"] as? String, let e = v["expiresAt"] as? Double, e > now else { return nil }
            return (t, e)
        }
        .max { $0.1 < $1.1 }?.0
}

func parseDate(_ s: Any?) -> Date? {
    guard var s = s as? String else { return nil }
    if let dot = s.firstIndex(of: "."), let tz = s[dot...].firstIndex(where: { $0 == "+" || $0 == "Z" || $0 == "-" }) {
        s.removeSubrange(dot..<tz)
    }
    return ISO8601DateFormatter().date(from: s)
}

func window(_ o: Any?) -> Window? {
    guard let d = o as? [String: Any], let u = d["utilization"] as? Double else { return nil }
    return Window(used: u, resetsAt: parseDate(d["resets_at"]))
}

func getJSON(_ path: String, _ tok: String) async throws -> [String: Any] {
    var r = URLRequest(url: URL(string: "https://api.anthropic.com/api/oauth/\(path)")!)
    r.setValue("Bearer \(tok)", forHTTPHeaderField: "Authorization")
    r.setValue("oauth-2025-04-20", forHTTPHeaderField: "anthropic-beta")
    r.setValue("claude-switcher/1.0", forHTTPHeaderField: "User-Agent")
    r.timeoutInterval = 15
    let (data, resp) = try await URLSession.shared.data(for: r)
    let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
    guard code == 200 else { throw err(code == 401 ? "Session expired — switch to it to re-auth" : "API error \(code)") }
    return try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:]
}

func planName(_ org: [String: Any]?) -> String? {
    let tier = (org?["rate_limit_tier"] as? String ?? "").lowercased()
    let type = (org?["organization_type"] as? String ?? "").lowercased()
    if tier.contains("20x") { return "Max 20x" }
    if tier.contains("5x") { return "Max 5x" }
    if type.contains("enterprise") { return "Enterprise" }
    if type.contains("team") { return "Team" }
    if type.contains("max") { return "Max" }
    if type.contains("pro") { return "Pro" }
    return type.isEmpty ? nil : type.capitalized
}

func fetchSnapshot(_ tok: String) async throws -> Snapshot {
    async let u = getJSON("usage", tok)
    async let p = getJSON("profile", tok)
    let (usage, prof) = try await (u, p)
    let acct = prof["account"] as? [String: Any]
    let org = prof["organization"] as? [String: Any]
    return Snapshot(email: acct?["email"] as? String,
                    name: org?["name"] as? String,
                    plan: planName(org),
                    session: window(usage["five_hour"]),
                    weekly: window(usage["seven_day"]),
                    weeklyOpus: window(usage["seven_day_opus"]),
                    extraEnabled: (usage["extra_usage"] as? [String: Any])?["is_enabled"] as? Bool,
                    fetchedAt: Date())
}

func loadCache(_ name: String) -> Snapshot? {
    guard let d = try? Data(contentsOf: cacheDir.appendingPathComponent("\(name).json")) else { return nil }
    let dec = JSONDecoder(); dec.dateDecodingStrategy = .iso8601
    return try? dec.decode(Snapshot.self, from: d)
}

func saveCache(_ name: String, _ s: Snapshot) {
    try? fm.createDirectory(at: cacheDir, withIntermediateDirectories: true)
    let enc = JSONEncoder(); enc.dateEncodingStrategy = .iso8601
    try? enc.encode(s).write(to: cacheDir.appendingPathComponent("\(name).json"))
}

// MARK: - Store

@MainActor
final class Store: ObservableObject {
    @Published var profiles: [Profile] = []
    @Published var current = currentProfile()
    @Published var claudeRunning = false
    @Published var busy: String?
    @Published var lastRefresh: Date?
    @Published var banner: String?
    @Published var openAtLogin = SMAppService.mainApp.status == .enabled
    var onChange: (() -> Void)?

    /// Fake accounts for README screenshots — touches no files, keychain or network.
    init(demo: Bool) {
        let now = Date()
        func snap(_ email: String, _ plan: String, _ s: Double, _ sh: Double, _ w: Double, _ wh: Double) -> Snapshot {
            Snapshot(email: email, name: nil, plan: plan,
                     session: Window(used: s, resetsAt: now.addingTimeInterval(sh * 3600)),
                     weekly: Window(used: w, resetsAt: now.addingTimeInterval(wh * 3600)),
                     weeklyOpus: nil, extraEnabled: false, fetchedAt: now)
        }
        current = "Personal"
        claudeRunning = true
        lastRefresh = now
        profiles = [
            Profile(name: "Personal", snapshot: snap("ada@lovelace.dev", "Max 5x", 28, 3.3, 61, 50), signedIn: true),
            Profile(name: "Business", snapshot: snap("ada@analytical.co", "Team", 86, 1.2, 74, 98), signedIn: true),
            Profile(name: "Side Project", snapshot: nil, signedIn: false),
        ]
    }

    func toggleOpenAtLogin() {
        do {
            if openAtLogin { try SMAppService.mainApp.unregister() } else { try SMAppService.mainApp.register() }
        } catch { banner = "Open at login failed: \(error.localizedDescription)" }
        openAtLogin = SMAppService.mainApp.status == .enabled
    }

    init() {
        try? fm.createDirectory(at: parkDir, withIntermediateDirectories: true)
        if !fm.fileExists(atPath: currentFile.path) {
            try? defaultProfiles[0].write(to: currentFile, atomically: true, encoding: .utf8)
        }
        for p in defaultProfiles where p != currentProfile() {
            try? fm.createDirectory(at: parkDir.appendingPathComponent(p), withIntermediateDirectories: true)
        }
        reloadList()
        Timer.scheduledTimer(withTimeInterval: 300, repeats: true) { _ in Task { @MainActor in await self.refresh() } }
        Task { await refresh() }
    }

    var active: Profile? { profiles.first { $0.name == current } }

    func reloadList() {
        current = currentProfile()
        claudeRunning = !NSRunningApplication.runningApplications(withBundleIdentifier: bundleID).isEmpty
        profiles = allProfileNames().map { n in
            profiles.first { $0.name == n } ?? Profile(name: n, snapshot: loadCache(n), signedIn: true)
        }
        onChange?()
    }

    func refresh() async {
        reloadList()
        banner = nil
        await withTaskGroup(of: (String, Result<Snapshot, Error>?).self) { g in
            for p in profiles {
                let dir = profileDir(p.name)
                g.addTask {
                    do {
                        guard let tok = try token(for: dir) else { return (p.name, nil) }
                        return (p.name, .success(try await fetchSnapshot(tok)))
                    } catch { return (p.name, .failure(error)) }
                }
            }
            for await (name, res) in g {
                guard let i = profiles.firstIndex(where: { $0.name == name }) else { continue }
                switch res {
                case nil: profiles[i].signedIn = false; profiles[i].error = nil
                case .success(let s)?: profiles[i].snapshot = s; profiles[i].signedIn = true; profiles[i].error = nil; saveCache(name, s)
                case .failure(let e)?:
                    profiles[i].error = e.localizedDescription
                    if e.localizedDescription.contains("Keychain") { banner = e.localizedDescription }
                }
            }
        }
        lastRefresh = Date()
        onChange?()
    }

    func addProfile(_ raw: String) {
        let name = raw.trimmingCharacters(in: .whitespaces).replacingOccurrences(of: "/", with: "-")
        guard !name.isEmpty, !name.hasPrefix("."), !profiles.contains(where: { $0.name == name }) else { return }
        try? fm.createDirectory(at: parkDir.appendingPathComponent(name), withIntermediateDirectories: true)
        reloadList()
        Task { await refresh() }
    }

    func switchTo(_ target: String) async {
        let cur = currentProfile()
        guard target != cur, busy == nil else { return }
        busy = "Quitting Claude…"
        defer { busy = nil }
        guard await quitClaude() else {
            banner = "Claude didn't quit. Close it manually, then switch again."
            return
        }
        busy = "Switching to \(target)…"
        do {
            let curPark = parkDir.appendingPathComponent(cur)
            let targetPark = parkDir.appendingPathComponent(target)
            if fm.fileExists(atPath: curPark.path) {
                // Only an empty placeholder may be replaced; anything else is real data.
                if ((try? fm.contentsOfDirectory(atPath: curPark.path)) ?? ["x"]).isEmpty {
                    try fm.removeItem(at: curPark)
                } else { throw err("\(curPark.path) already exists; refusing to overwrite.") }
            }
            if fm.fileExists(atPath: liveDir.path) { try fm.moveItem(at: liveDir, to: curPark) }
            if fm.fileExists(atPath: targetPark.path) { try fm.moveItem(at: targetPark, to: liveDir) }
            try target.write(to: currentFile, atomically: true, encoding: .utf8)
        } catch {
            banner = "Switch failed: \(error.localizedDescription)"
            return
        }
        busy = "Opening Claude…"
        await launchClaude()
        reloadList()
        await refresh()
    }

    /// Copies threads into another profile. If that profile is live and Claude is running,
    /// Claude is restarted so it picks the new threads up.
    func copyThreads(_ threads: [ThreadInfo], to target: String) async -> String {
        guard busy == nil else { return "Busy, try again in a moment." }
        let restart = target == currentProfile()
            && !NSRunningApplication.runningApplications(withBundleIdentifier: bundleID).isEmpty
        if restart {
            busy = "Quitting Claude…"
            guard await quitClaude() else { busy = nil; return "Claude didn't quit. Close it manually and try again." }
        }
        busy = "Copying \(threads.count) threads…"
        let result: String
        do {
            let (copied, skipped) = try copyThreadFiles(threads, to: profileDir(target))
            result = "Copied \(copied) thread\(copied == 1 ? "" : "s") to \(target)"
                + (skipped > 0 ? " (\(skipped) already there)" : "") + "."
        } catch { result = "Copy failed: \(error.localizedDescription)" }
        if restart { busy = "Opening Claude…"; await launchClaude() }
        busy = nil
        reloadList()
        return result
    }
}

func quitClaude() async -> Bool {
    let running = { NSRunningApplication.runningApplications(withBundleIdentifier: bundleID) }
    running().forEach { $0.terminate() }
    for _ in 0..<60 where !running().isEmpty { try? await Task.sleep(nanoseconds: 250_000_000) }
    return running().isEmpty
}

func launchClaude() async {
    if let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: bundleID) {
        _ = try? await NSWorkspace.shared.openApplication(at: url, configuration: .init())
    }
}

// MARK: - Claude Code threads
//
// Each desktop Code thread is one JSON file in <profile>/claude-code-sessions/<account>/<org>/.
// The conversation itself lives in the shared ~/.claude/projects, so copying the JSON is enough
// for another account to resume it.

struct ThreadInfo: Identifiable, Hashable {
    var id: String { file.lastPathComponent }
    let file: URL
    let title: String
    let cwd: String
    let lastActivity: Date
    let archived: Bool
    var project: String { (cwd as NSString).lastPathComponent }
}

/// Fields tied to the source account: its connectors, remote-control bridge and armed scheduled work.
let accountBoundThreadKeys = ["remoteMcpServersConfig", "bridgeSessionIds", "armedWorkAtQuit"]

/// The <account>/<org> folder holding a profile's threads, preferring its last signed-in account.
func threadsDir(_ profile: URL) -> URL? {
    let root = profile.appendingPathComponent("claude-code-sessions")
    let acctPref = ((try? Data(contentsOf: profile.appendingPathComponent("config.json")))
        .flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] })?["lastKnownAccountUuid"] as? String
    let accts = ((try? fm.contentsOfDirectory(atPath: root.path)) ?? []).filter { !$0.hasPrefix(".") }
    guard let acct = accts.first(where: { $0 == acctPref }) ?? accts.first else { return nil }
    let acctDir = root.appendingPathComponent(acct)
    let orgs = ((try? fm.contentsOfDirectory(atPath: acctDir.path)) ?? []).filter { !$0.hasPrefix(".") }
    return orgs.first.map { acctDir.appendingPathComponent($0) }
}

func listThreads(_ profile: String) -> [ThreadInfo] {
    guard let dir = threadsDir(profileDir(profile)) else { return [] }
    let files = ((try? fm.contentsOfDirectory(atPath: dir.path)) ?? [])
        .filter { $0.hasPrefix("local_") && $0.hasSuffix(".json") }
    return files.compactMap { name -> ThreadInfo? in
        let url = dir.appendingPathComponent(name)
        guard let d = try? Data(contentsOf: url),
              let j = try? JSONSerialization.jsonObject(with: d) as? [String: Any],
              let cwd = j["cwd"] as? String,
              !cwd.contains("/Library/Application Support/") // scratch threads inside the profile folder
        else { return nil }
        let t = (j["lastActivityAt"] as? Double) ?? (j["createdAt"] as? Double) ?? 0
        return ThreadInfo(file: url, title: (j["title"] as? String) ?? "Untitled", cwd: cwd,
                          lastActivity: Date(timeIntervalSince1970: t / 1000),
                          archived: (j["isArchived"] as? Bool) ?? false)
    }.sorted { $0.lastActivity > $1.lastActivity }
}

func copyThreadFiles(_ threads: [ThreadInfo], to profile: URL) throws -> (copied: Int, skipped: Int) {
    guard let dest = threadsDir(profile) else {
        throw err("That account hasn't used Claude Code yet. Switch to it, open the Code tab once, then copy.")
    }
    var copied = 0, skipped = 0
    for t in threads {
        let out = dest.appendingPathComponent(t.file.lastPathComponent)
        if fm.fileExists(atPath: out.path) { skipped += 1; continue }
        guard var j = try JSONSerialization.jsonObject(with: Data(contentsOf: t.file)) as? [String: Any] else { continue }
        accountBoundThreadKeys.forEach { j.removeValue(forKey: $0) }
        try JSONSerialization.data(withJSONObject: j).write(to: out, options: .atomic)
        copied += 1
    }
    return (copied, skipped)
}

// MARK: - Formatting

func left(_ w: Window?) -> Double? { w.map { max(0, 100 - $0.used) } }
func pct(_ v: Double?) -> String { v.map { String(Int($0.rounded())) } ?? "--" }

func countdown(_ d: Date?) -> String {
    guard let d else { return "--" }
    let s = Int(d.timeIntervalSinceNow)
    if s <= 0 { return "now" }
    let h = s / 3600, m = (s % 3600) / 60
    return h > 0 ? "in \(h)h \(m)m" : "in \(m)m"
}

func weekdayTime(_ d: Date?) -> String {
    guard let d else { return "--" }
    let f = DateFormatter(); f.dateFormat = "EEE h:mm a"
    return f.string(from: d).uppercased()
}

func ago(_ d: Date?) -> String {
    guard let d else { return "never" }
    let s = Int(-d.timeIntervalSinceNow)
    if s < 60 { return "just now" }
    if s < 3600 { return "\(s / 60)m ago" }
    if s < 86400 { return "\(s / 3600)h ago" }
    return "\(s / 86400)d ago"
}

// MARK: - Views

struct Pill: View {
    let text: String; let fg: Color; let bg: Color
    var body: some View {
        Text(text).font(.system(size: 11, weight: .heavy)).tracking(0.6)
            .padding(.horizontal, 12).padding(.vertical, 7)
            .foregroundColor(fg).background(RoundedRectangle(cornerRadius: 9).fill(bg))
    }
}

struct Bar: View {
    let value: Double?; let color: Color; var height: CGFloat = 6
    var body: some View {
        GeometryReader { g in
            ZStack(alignment: .leading) {
                Capsule().fill(Color.stroke)
                Capsule().fill(color).frame(width: g.size.width * CGFloat((value ?? 0) / 100))
            }
        }.frame(height: height)
    }
}

struct Header: View {
    @ObservedObject var store: Store
    var body: some View {
        let a = store.active, s = a?.snapshot
        HStack(spacing: 14) {
            ZStack {
                RoundedRectangle(cornerRadius: 14).fill(Color.claude.opacity(0.15))
                RoundedRectangle(cornerRadius: 14).stroke(Color.claude.opacity(0.5), lineWidth: 1)
                Text("✳︎").font(.system(size: 26, weight: .bold)).foregroundColor(.claude)
            }.frame(width: 52, height: 52)
            VStack(alignment: .leading, spacing: 3) {
                Text("CLAUDE ACCOUNT SWITCHER").font(.system(size: 10.5, weight: .bold)).tracking(1).foregroundColor(.sub)
                Text("\(store.current) is live").font(.system(size: 20, weight: .bold)).foregroundColor(.txt)
                Text([s?.email ?? (a?.signedIn == false ? "Not signed in" : "…"), s?.plan].compactMap { $0 }.joined(separator: "  ·  "))
                    .font(.system(size: 11.5, weight: .medium)).foregroundColor(.sub).lineLimit(1)
            }
            Spacer(minLength: 0)
            let on = store.claudeRunning
            HStack(spacing: 6) {
                Circle().fill(on ? Color.good : Color.sub).frame(width: 7, height: 7)
                Text(on ? "RUNNING" : "CLOSED").font(.system(size: 10.5, weight: .heavy)).tracking(0.6)
            }
            .foregroundColor(on ? .good : .sub)
            .padding(.horizontal, 12).padding(.vertical, 8)
            .background(RoundedRectangle(cornerRadius: 10).fill((on ? Color.good : Color.sub).opacity(0.12)))
            .overlay(RoundedRectangle(cornerRadius: 10).stroke((on ? Color.good : Color.sub).opacity(0.35)))
        }
        .padding(14)
        .background(RoundedRectangle(cornerRadius: 18).fill(Color.card))
    }
}

struct ProfileCard: View {
    let p: Profile
    let active: Bool
    let busy: Bool
    let onSwitch: () -> Void
    @State private var hover = false

    var body: some View {
        let s = p.snapshot
        let sl = left(s?.session), wl = left(s?.weekly)
        let c = levelColor(sl)
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 3) {
                    Text(p.name).font(.system(size: 15, weight: .bold)).foregroundColor(active ? .claude : .txt)
                        .lineLimit(1).fixedSize(horizontal: false, vertical: true)
                    HStack(spacing: 6) {
                        if let plan = s?.plan {
                            Text(plan.uppercased()).font(.system(size: 9, weight: .heavy)).tracking(0.5)
                                .padding(.horizontal, 6).padding(.vertical, 3).fixedSize()
                                .foregroundColor(.sub).background(RoundedRectangle(cornerRadius: 5).fill(Color.stroke))
                        }
                        Text(p.signedIn ? (s?.email ?? "—") : "Not signed in yet")
                            .font(.system(size: 11)).foregroundColor(.sub).lineLimit(1).truncationMode(.middle)
                    }
                }
                Spacer(minLength: 6)
                if active {
                    Pill(text: "ACTIVE", fg: .white, bg: .claude)
                } else {
                    Button(action: onSwitch) {
                        Pill(text: "SWITCH", fg: .txt, bg: hover ? Color(hex: 0x45423C) : .stroke)
                    }
                    .buttonStyle(.plain).disabled(busy).onHover { hover = $0 }
                }
            }

            if p.signedIn && s != nil {
                HStack(alignment: .lastTextBaseline) {
                    HStack(alignment: .lastTextBaseline, spacing: 1) {
                        Text(pct(sl)).font(.system(size: 46, weight: .heavy, design: .rounded))
                        Text("%").font(.system(size: 18, weight: .heavy, design: .rounded))
                    }.foregroundColor(c)
                    Spacer()
                    VStack(alignment: .trailing, spacing: 3) {
                        Text("5-hour left").font(.system(size: 12, weight: .semibold)).foregroundColor(.sub)
                        Text("resets \(countdown(s?.session?.resetsAt))").font(.system(size: 11)).foregroundColor(.sub.opacity(0.8))
                    }
                }
                Bar(value: sl, color: c)
                Divider().background(Color.stroke).padding(.vertical, 2)
                HStack(alignment: .top) {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Weekly left").font(.system(size: 11.5, weight: .medium)).foregroundColor(.sub)
                        Text("\(pct(wl))%").font(.system(size: 20, weight: .bold, design: .rounded)).foregroundColor(levelColor(wl))
                    }
                    Spacer()
                    Rectangle().fill(Color.stroke).frame(width: 1, height: 40)
                    Spacer()
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Weekly reset").font(.system(size: 11.5, weight: .medium)).foregroundColor(.sub)
                        Text(weekdayTime(s?.weekly?.resetsAt)).font(.system(size: 15, weight: .bold, design: .rounded))
                            .foregroundColor(active ? .claude : .txt).padding(.top, 3)
                    }
                }
                Bar(value: wl, color: levelColor(wl), height: 4)
                if let e = p.error {
                    Label(e, systemImage: "exclamationmark.triangle.fill").font(.system(size: 10)).foregroundColor(.warn).lineLimit(2)
                } else if !p.live, let s {
                    Text("as of \(ago(s.fetchedAt))").font(.system(size: 10)).foregroundColor(.sub)
                }
            } else {
                Spacer()
                VStack(spacing: 8) {
                    Image(systemName: p.signedIn ? "arrow.triangle.2.circlepath" : "person.crop.circle.badge.plus")
                        .font(.system(size: 28)).foregroundColor(.sub)
                    Text(p.error ?? (p.signedIn ? "Loading…" : "Switch, then sign in to Claude"))
                        .font(.system(size: 11.5)).foregroundColor(.sub).multilineTextAlignment(.center)
                }.frame(maxWidth: .infinity)
                Spacer()
            }
        }
        .padding(16)
        .frame(height: 236)
        .background(RoundedRectangle(cornerRadius: 18).fill(active ? Color.cardHi : Color.card))
        .overlay(RoundedRectangle(cornerRadius: 18).stroke(active ? Color.claude.opacity(0.7) : Color.clear, lineWidth: 1.5))
        .overlay(alignment: .leading) {
            if active { Capsule().fill(Color.claude).frame(width: 3).padding(.vertical, 22) }
        }
    }
}

struct AddCard: View {
    let onAdd: (String) -> Void
    @State private var editing = false
    @State private var name = ""
    var body: some View {
        VStack(spacing: 12) {
            if editing {
                Text("Profile name").font(.system(size: 12, weight: .semibold)).foregroundColor(.sub)
                TextField("e.g. Client X", text: $name, onCommit: commit)
                    .textFieldStyle(.roundedBorder).frame(width: 150)
                HStack {
                    Button("Cancel") { editing = false; name = "" }
                    Button("Add", action: commit).keyboardShortcut(.defaultAction)
                }.font(.system(size: 11))
            } else {
                Image(systemName: "plus").font(.system(size: 22, weight: .light)).foregroundColor(.sub)
                Text("Add another account").font(.system(size: 13, weight: .semibold)).foregroundColor(.sub)
            }
        }
        .frame(maxWidth: .infinity).frame(height: 236)
        .background(RoundedRectangle(cornerRadius: 18).fill(Color.card))
        .overlay(RoundedRectangle(cornerRadius: 18).stroke(Color.stroke, style: StrokeStyle(lineWidth: 1, dash: [5, 4])))
        .contentShape(Rectangle())
        .onTapGesture { if !editing { editing = true } }
    }
    func commit() { onAdd(name); name = ""; editing = false }
}

struct FooterButton: View {
    let icon: String; let help: String; let action: () -> Void
    @State private var hover = false
    var body: some View {
        Button(action: action) {
            Image(systemName: icon).font(.system(size: 14, weight: .medium))
                .foregroundColor(hover ? .txt : .sub).frame(width: 32, height: 32)
                .background(RoundedRectangle(cornerRadius: 8).fill(hover ? Color.stroke : .clear))
        }.buttonStyle(.plain).help(help).onHover { hover = $0 }
    }
}

struct Panel: View {
    @ObservedObject var store: Store
    let cols = [GridItem(.flexible(), spacing: 12), GridItem(.flexible(), spacing: 12)]

    var body: some View {
        VStack(spacing: 12) {
            Header(store: store)
            if let b = store.banner {
                Label(b, systemImage: "exclamationmark.triangle.fill").font(.system(size: 11.5))
                    .foregroundColor(.warn).frame(maxWidth: .infinity, alignment: .leading)
                    .padding(10).background(RoundedRectangle(cornerRadius: 10).fill(Color.warn.opacity(0.1)))
            }
            LazyVGrid(columns: cols, spacing: 12) {
                ForEach(store.profiles) { p in
                    ProfileCard(p: p, active: p.name == store.current, busy: store.busy != nil) {
                        Task { await store.switchTo(p.name) }
                    }
                }
                AddCard { store.addProfile($0) }
            }
            HStack(spacing: 10) {
                FooterButton(icon: "folder", help: "Show profiles folder") {
                    NSWorkspace.shared.activateFileViewerSelecting([parkDir])
                }
                FooterButton(icon: "arrow.right.doc.on.clipboard", help: "Copy Claude Code threads between accounts") {
                    CopyWindow.show(store)
                }
                Rectangle().fill(Color.stroke).frame(width: 1, height: 22)
                if let b = store.busy {
                    ProgressView().controlSize(.small)
                    Text(b).font(.system(size: 13, weight: .semibold)).foregroundColor(.claude)
                } else {
                    Image(systemName: "clock").foregroundColor(.sub)
                    TimelineView(.periodic(from: .now, by: 30)) { _ in
                        Text(ago(store.lastRefresh)).font(.system(size: 13, weight: .semibold)).foregroundColor(.txt)
                    }
                }
                Spacer()
                FooterButton(icon: "arrow.clockwise", help: "Refresh") { Task { await store.refresh() } }
                Rectangle().fill(Color.stroke).frame(width: 1, height: 22)
                FooterButton(icon: store.openAtLogin ? "sunrise.fill" : "sunrise",
                             help: store.openAtLogin ? "Opens at login (click to disable)" : "Open at login") {
                    store.toggleOpenAtLogin()
                }
                FooterButton(icon: "power", help: "Quit Claude Switcher") { NSApp.terminate(nil) }
            }
            .padding(.horizontal, 12).padding(.vertical, 8)
            .background(RoundedRectangle(cornerRadius: 16).fill(Color.card))
        }
        .padding(14)
        .frame(width: 480)
        .background(Color.bg)
        .preferredColorScheme(.dark)
    }
}

// MARK: - Copy threads window

struct CopyThreadsView: View {
    @ObservedObject var store: Store
    @State private var from = ""
    @State private var to = ""
    @State private var threads: [ThreadInfo] = []
    @State private var picked = Set<String>()
    @State private var query = ""
    @State private var showArchived = false
    @State private var status: String?

    var names: [String] { store.profiles.map(\.name) }
    var visible: [ThreadInfo] {
        threads.filter { (showArchived || !$0.archived)
            && (query.isEmpty || "\($0.title) \($0.cwd)".localizedCaseInsensitiveContains(query)) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 10) {
                picker("From", $from)
                Image(systemName: "arrow.right").foregroundColor(.claude)
                picker("To", $to)
                Spacer()
            }
            HStack {
                TextField("Search threads or projects", text: $query).textFieldStyle(.roundedBorder)
                Toggle("Archived", isOn: $showArchived).toggleStyle(.checkbox)
            }
            HStack {
                Button(allPicked ? "Select none" : "Select all") {
                    if allPicked { visible.forEach { picked.remove($0.id) } } else { visible.forEach { picked.insert($0.id) } }
                }.buttonStyle(.link)
                Spacer()
                Text("\(picked.count) selected · \(visible.count) shown").font(.system(size: 11)).foregroundColor(.sub)
            }
            List(visible) { t in
                HStack(spacing: 10) {
                    Toggle("", isOn: Binding(get: { picked.contains(t.id) },
                                             set: { on in if on { picked.insert(t.id) } else { picked.remove(t.id) } }))
                        .toggleStyle(.checkbox).labelsHidden()
                    VStack(alignment: .leading, spacing: 2) {
                        Text(t.title).font(.system(size: 13, weight: .semibold)).foregroundColor(.txt).lineLimit(1)
                        Text(t.cwd.replacingOccurrences(of: NSHomeDirectory(), with: "~"))
                            .font(.system(size: 11)).foregroundColor(.sub).lineLimit(1).truncationMode(.middle)
                    }
                    Spacer()
                    Text(t.project).font(.system(size: 10, weight: .bold)).padding(.horizontal, 6).padding(.vertical, 3)
                        .foregroundColor(.sub).background(RoundedRectangle(cornerRadius: 5).fill(Color.stroke))
                    Text(ago(t.lastActivity)).font(.system(size: 11)).foregroundColor(.sub).frame(width: 60, alignment: .trailing)
                }
                .padding(.vertical, 3)
                .contentShape(Rectangle())
                .onTapGesture { if picked.contains(t.id) { picked.remove(t.id) } else { picked.insert(t.id) } }
            }
            .listStyle(.inset(alternatesRowBackgrounds: false))
            .overlay { if visible.isEmpty { Text(from.isEmpty ? "" : "No threads in \(from)").foregroundColor(.sub) } }
            HStack {
                if let b = store.busy {
                    ProgressView().controlSize(.small); Text(b).foregroundColor(.claude)
                } else if let s = status {
                    Text(s).font(.system(size: 12)).foregroundColor(s.hasPrefix("Copied") ? .good : .warn).lineLimit(2)
                }
                Spacer()
                Button("Copy \(picked.count) to \(to)") {
                    let sel = threads.filter { picked.contains($0.id) }
                    Task {
                        status = await store.copyThreads(sel, to: to)
                        if status?.hasPrefix("Copied") == true { picked.removeAll() }
                    }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(picked.isEmpty || from == to || store.busy != nil)
            }
            if to == store.current && store.claudeRunning {
                Text("Claude will restart so \(to) picks up the copied threads.").font(.system(size: 11)).foregroundColor(.sub)
            }
        }
        .padding(16)
        .frame(minWidth: 620, minHeight: 520)
        .background(Color.bg)
        .preferredColorScheme(.dark)
        .onAppear {
            to = store.current
            from = names.filter { $0 != to }.max { listThreads($0).count < listThreads($1).count } ?? to
            load()
        }
        .onChange(of: from) { _ in load() }
    }

    var allPicked: Bool { !visible.isEmpty && visible.allSatisfy { picked.contains($0.id) } }

    func load() { threads = listThreads(from); picked.removeAll(); status = nil }

    func picker(_ label: String, _ sel: Binding<String>) -> some View {
        Picker(label, selection: sel) { ForEach(names, id: \.self) { Text($0).tag($0) } }.frame(width: 190)
    }
}

enum CopyWindow {
    static var window: NSWindow?
    @MainActor static func show(_ store: Store) {
        if window == nil {
            let w = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 680, height: 580),
                             styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
            w.title = "Copy Claude Code Threads"
            w.isReleasedWhenClosed = false
            w.appearance = NSAppearance(named: .darkAqua)
            w.contentViewController = NSHostingController(rootView: CopyThreadsView(store: store))
            w.center()
            window = w
        }
        NSApp.activate(ignoringOtherApps: true)
        window?.makeKeyAndOrderFront(nil)
    }
}

// MARK: - App

final class AppDelegate: NSObject, NSApplicationDelegate {
    let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    let popover = NSPopover()
    var store: Store!

    func applicationDidFinishLaunching(_ n: Notification) {
        MainActor.assumeIsolated {
            store = Store()
            store.onChange = { [weak self] in self?.updateTitle() }
            popover.behavior = .transient
            popover.animates = true
            popover.appearance = NSAppearance(named: .darkAqua)
            let host = NSHostingController(rootView: Panel(store: store))
            // Let the popover track the SwiftUI size; otherwise it's positioned at its initial
            // (too small) size and the grown content spills up past the menu bar.
            host.sizingOptions = [.preferredContentSize]
            popover.contentViewController = host
            item.button?.target = self
            item.button?.action = #selector(toggle)
            updateTitle()
        }
    }

    @MainActor func updateTitle() {
        guard let b = item.button else { return }
        let sl = left(store.active?.snapshot?.session)
        let initial = store.current.prefix(1).uppercased()
        b.title = sl.map { " \(initial) · \(pct($0))%" } ?? " \(initial)"
        b.image = NSImage(systemSymbolName: "sparkle", accessibilityDescription: "Claude Switcher")
        b.imagePosition = .imageLeading
        b.toolTip = "Claude: \(store.current)"
    }

    @objc func toggle() {
        MainActor.assumeIsolated {
            if popover.isShown { popover.performClose(nil); return }
            guard let b = item.button else { return }
            Task { await store.refresh() }
            if let v = popover.contentViewController?.view {
                v.layoutSubtreeIfNeeded()
                popover.contentSize = v.fittingSize
            }
            popover.show(relativeTo: b.bounds, of: b, preferredEdge: .minY)
            popover.contentViewController?.view.window?.makeKey()
            NSApp.activate(ignoringOtherApps: true)
        }
    }
}

let app = NSApplication.shared
// `ClaudeSwitcher --snapshot out.png [--demo]` renders the panel to a PNG and exits.
if let i = CommandLine.arguments.firstIndex(of: "--snapshot"), i + 1 < CommandLine.arguments.count {
    let out = URL(fileURLWithPath: CommandLine.arguments[i + 1])
    MainActor.assumeIsolated {
        let demo = CommandLine.arguments.contains("--demo")
        let store = demo ? Store(demo: true) : Store()
        Task { @MainActor in
            if !demo { await store.refresh() }
            let r = CommandLine.arguments.contains("--copy")
                ? ImageRenderer(content: AnyView(CopyThreadsView(store: store).frame(width: 680, height: 580)))
                : ImageRenderer(content: AnyView(Panel(store: store)))
            r.scale = 2
            if let cg = r.cgImage {
                try? NSBitmapImageRep(cgImage: cg).representation(using: .png, properties: [:])?.write(to: out)
            }
            exit(0)
        }
    }
    app.run()
}
// `ClaudeSwitcher --register-login` adds the app to Login Items and exits (used by `build.sh install`).
if CommandLine.arguments.contains("--register-login") {
    do { try SMAppService.mainApp.register(); exit(0) } catch { print("register failed: \(error)"); exit(1) }
}
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()

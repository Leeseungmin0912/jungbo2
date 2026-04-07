import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import re
import os
import webbrowser
import subprocess
import csv
from collections import Counter, defaultdict
from datetime import datetime

selected_file = None
analysis_result = {}
suspicious_targets = set()
MAX_SCORE = 100

# 대상(IP/계정)별 상세 통계 저장용
target_stats = {}


def log_message(msg):
    output_box.config(state="normal")
    output_box.insert(tk.END, msg + "\n")
    output_box.see(tk.END)
    output_box.config(state="disabled")


def set_status(msg):
    status_var.set(msg)


def clear_analysis_boxes_only():
    global analysis_result, suspicious_targets, target_stats
    analysis_result = {}
    suspicious_targets = set()
    target_stats = {}

    output_box.config(state="normal")
    output_box.delete("1.0", tk.END)
    output_box.config(state="disabled")

    result_box.config(state="normal")
    result_box.delete("1.0", tk.END)
    result_box.config(state="disabled")

    suspicious_box.config(state="normal")
    suspicious_box.delete("1.0", tk.END)
    suspicious_box.config(state="disabled")

    score_var.set(f"0 / {MAX_SCORE}")
    grade_var.set("-")
    total_logs_var.set("0")
    fail_count_var.set("0")
    warn_count_var.set("0")

    grade_value_label.config(fg="#222222")
    badge_canvas.itemconfig(badge_circle, fill="#b0b7c3", outline="#b0b7c3")


def clear_output():
    global selected_file
    selected_file = None
    clear_analysis_boxes_only()
    file_var.set("선택된 파일 없음")
    set_status("초기화 완료")


def select_log_file():
    global selected_file
    file_path = filedialog.askopenfilename(
        title="로그 파일 선택",
        filetypes=[("Log files", "*.log *.txt *.csv"), ("All files", "*.*")]
    )

    if file_path:
        selected_file = file_path
        file_var.set(os.path.basename(file_path))
        log_message(f"[파일 선택] {file_path}")
        set_status(f"파일 선택 완료: {file_path}")


def export_security_log_csv():
    save_path = filedialog.asksaveasfilename(
        title="Security 로그 CSV 저장",
        defaultextension=".csv",
        filetypes=[("CSV files", "*.csv")]
    )

    if not save_path:
        return

    set_status("Windows Security 로그 CSV 저장 중...")
    log_message("[시작] Windows Security 로그를 CSV로 저장합니다.")

    ps_script = f"""
$ErrorActionPreference = 'Stop'
Get-WinEvent -LogName Security -MaxEvents 50 |
Select-Object TimeCreated, Id, LevelDisplayName, Message |
Export-Csv -Path '{save_path}' -NoTypeInformation -Encoding UTF8
"""

    try:
        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy", "Bypass",
                "-Command", ps_script
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace"
        )

        if result.returncode != 0:
            err = result.stderr.strip() if result.stderr else "알 수 없는 오류"
            messagebox.showerror(
                "오류",
                "Security 로그 CSV 저장에 실패했습니다.\n\n"
                "가능한 원인:\n"
                "- PowerShell 관리자 권한 필요\n"
                "- Security 로그 접근 권한 부족\n"
                "- 저장 경로 문제\n\n"
                f"상세 오류:\n{err}"
            )
            log_message(f"[오류] Security CSV 저장 실패: {err}")
            set_status("Security 로그 CSV 저장 실패")
            return

        messagebox.showinfo("완료", f"Security 로그 CSV가 저장되었습니다.\n{save_path}")
        log_message(f"[완료] Security CSV 저장: {save_path}")
        set_status(f"Security 로그 CSV 저장 완료: {save_path}")

        open_now = messagebox.askyesno("열기", "저장된 CSV 파일을 바로 열까요?")
        if open_now:
            os.startfile(save_path)

    except FileNotFoundError:
        messagebox.showerror("오류", "PowerShell을 찾을 수 없습니다.")
        log_message("[오류] PowerShell 실행 파일을 찾을 수 없습니다.")
        set_status("PowerShell 실행 실패")
    except Exception as e:
        messagebox.showerror("오류", f"Security 로그 CSV 저장 중 예외 발생:\n{e}")
        log_message(f"[오류] Security CSV 저장 중 예외: {e}")
        set_status("Security 로그 CSV 저장 실패")


def detect_log_type(file_path):
    try:
        with open(file_path, "r", encoding="utf-8-sig") as f:
            first_chunk = f.read(2000)
    except UnicodeDecodeError:
        try:
            with open(file_path, "r", encoding="cp949") as f:
                first_chunk = f.read(2000)
        except Exception:
            return "unknown"
    except Exception:
        return "unknown"

    if (
        "TimeCreated" in first_chunk
        and "LevelDisplayName" in first_chunk
        and "Message" in first_chunk
    ):
        return "security_csv"

    if (
        "IP=" in first_chunk
        or "ACTION=" in first_chunk
        or "URL=" in first_chunk
        or "CODE=" in first_chunk
    ):
        return "web_log"

    return "unknown"


def read_text_lines(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return f.readlines()
    except UnicodeDecodeError:
        with open(file_path, "r", encoding="cp949") as f:
            return f.readlines()


def parse_datetime(line):
    match = re.search(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", line)
    if match:
        try:
            return datetime.strptime(match.group(1), "%Y-%m-%d %H:%M:%S")
        except Exception:
            return None
    return None


def parse_csv_datetime(value):
    if not value:
        return None

    value = str(value).strip()

    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %p %I:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%m/%d/%Y %I:%M:%S %p",
        "%Y-%m-%d 오후 %I:%M:%S",
        "%Y-%m-%d 오전 %I:%M:%S",
    ]

    for fmt in formats:
        try:
            return datetime.strptime(value, fmt)
        except Exception:
            continue

    cleaned = value.replace("Z", "").split(".")[0]
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(cleaned, fmt)
        except Exception:
            continue

    return None


def format_dt(dt_obj):
    if not dt_obj:
        return "-"

    hour = dt_obj.hour
    am_pm = "오전" if hour < 12 else "오후"

    hour12 = hour % 12
    if hour == 0:
        hour12 = 12

    return f"{dt_obj.year}-{dt_obj.month:02d}-{dt_obj.day:02d} {am_pm} {hour12:02d}:{dt_obj.minute:02d}:{dt_obj.second:02d}"


def extract_ip(line):
    match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
    if match:
        return match.group(0)
    return None


def extract_url(line):
    match = re.search(r"URL=([^\s]+)", line)
    if match:
        return match.group(1)
    return None


def extract_code(line):
    match = re.search(r"CODE=(\d{3})", line)
    if match:
        return int(match.group(1))
    return None


def is_login_fail(line):
    return "ACTION=LOGIN" in line and "STATUS=FAIL" in line


def extract_account_from_message(message):
    patterns = [
        r"Account Name:\s*([^\r\n]+)",
        r"계정 이름:\s*([^\r\n]+)",
        r"Target Account Name:\s*([^\r\n]+)",
        r"New Account Name:\s*([^\r\n]+)",
        r"Subject:\s*.*?Account Name:\s*([^\r\n]+)",
    ]

    for pattern in patterns:
        match = re.search(pattern, message, re.IGNORECASE | re.DOTALL)
        if match:
            value = match.group(1).strip()
            if value and value != "-":
                return value

    return "알 수 없음"


def normalize_target_name(name):
    if not name:
        return ""
    return str(name).strip()


def get_my_computer_name():
    return os.environ.get("COMPUTERNAME", "").strip()


def get_my_username():
    return os.environ.get("USERNAME", "").strip()


def get_excluded_accounts():
    excluded = {
        get_my_computer_name(),
        get_my_username(),
        f"{get_my_computer_name()}$",
        "SYSTEM",
        "LOCAL SERVICE",
        "NETWORK SERVICE",
        "ANONYMOUS LOGON",
        "Window Manager",
        "Font Driver Host",
    }
    return {item.strip() for item in excluded if item and str(item).strip()}


def is_builtin_account(account):
    if not account:
        return True

    value = account.strip()
    upper = value.upper()

    if upper in {
        "SYSTEM",
        "LOCAL SERVICE",
        "NETWORK SERVICE",
        "ANONYMOUS LOGON",
        "WINDOW MANAGER",
        "FONT DRIVER HOST",
    }:
        return True

    if upper.startswith("DWM-") or upper.startswith("UMFD-"):
        return True

    if value.endswith("$"):
        return True

    return False


def is_my_device_or_account(account):
    if not account:
        return False

    value = account.strip()
    value_upper = value.upper()

    computer_name = get_my_computer_name().strip()
    username = get_my_username().strip()

    compare_targets = {
        computer_name.upper() if computer_name else "",
        username.upper() if username else "",
        (computer_name + "$").upper() if computer_name else "",
    }

    compare_targets = {x for x in compare_targets if x}

    return value_upper in compare_targets


def should_exclude_account(account):
    if not account:
        return True

    value = normalize_target_name(account)
    if value == "알 수 없음":
        return True

    if value in get_excluded_accounts():
        return True

    if is_builtin_account(value):
        return True

    if is_my_device_or_account(value):
        return True

    return False


def add_suspicious_target(target):
    if not target:
        return
    suspicious_targets.add(target.strip())


def get_grade(score):
    if score >= 80:
        return "매우 높음"
    if score >= 50:
        return "높음"
    if score >= 20:
        return "주의"
    return "낮음"


def get_grade_color(grade):
    colors = {
        "낮음": "#2e8b57",
        "주의": "#c99700",
        "높음": "#ff7a00",
        "매우 높음": "#d62828"
    }
    return colors.get(grade, "#222222")


def update_grade_badge(grade):
    color = get_grade_color(grade)
    grade_value_label.config(fg=color)
    badge_canvas.itemconfig(badge_circle, fill=color, outline=color)


def ensure_target_stats(target_name):
    if target_name not in target_stats:
        target_stats[target_name] = {
            "type": "unknown",
            "total_requests": 0,
            "login_fail": 0,
            "admin_access": 0,
            "code_404": 0,
            "code_500": 0,
            "night_access": 0,
            "event_4624": 0,
            "event_4625": 0,
            "event_4740": 0,
            "other_events": 0,
        }


def analyze_web_log(lines):
    global suspicious_targets, target_stats

    total_logs = 0
    login_fail_count = 0
    warning_count = 0
    risk_score = 0

    ip_login_fail = Counter()
    ip_admin_access = Counter()
    ip_404_count = Counter()
    ip_500_count = Counter()
    ip_night_access = Counter()
    ip_request_count = Counter()

    findings = []

    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue

        total_logs += 1
        ip = extract_ip(line)
        dt = parse_datetime(line)
        url = extract_url(line)
        code = extract_code(line)

        if ip:
            ensure_target_stats(ip)
            target_stats[ip]["type"] = "IP"
            ip_request_count[ip] += 1
            target_stats[ip]["total_requests"] += 1

        if is_login_fail(line):
            login_fail_count += 1
            if ip:
                ip_login_fail[ip] += 1
                target_stats[ip]["login_fail"] += 1

        if url:
            danger_paths = ["/admin", "/wp-admin", "/login", "/config"]
            for path in danger_paths:
                if path in url:
                    if ip:
                        ip_admin_access[ip] += 1
                        target_stats[ip]["admin_access"] += 1
                    break

        if code == 404 and ip:
            ip_404_count[ip] += 1
            target_stats[ip]["code_404"] += 1

        if code == 500 and ip:
            ip_500_count[ip] += 1
            target_stats[ip]["code_500"] += 1

        if dt and ip and 0 <= dt.hour <= 5:
            ip_night_access[ip] += 1
            target_stats[ip]["night_access"] += 1

    for ip, count in ip_login_fail.items():
        if count >= 5:
            findings.append(f"[위험] 로그인 실패 {count}회 | {ip}")
            risk_score += 20
            warning_count += 1
            add_suspicious_target(ip)

    for ip, count in ip_admin_access.items():
        if count >= 1:
            findings.append(f"[주의] 민감 경로 접근 {count}회 | {ip}")
            risk_score += 15
            warning_count += 1
            add_suspicious_target(ip)

    for ip, count in ip_404_count.items():
        if count >= 3:
            findings.append(f"[주의] 404 반복 {count}회 | {ip}")
            risk_score += 10
            warning_count += 1
            add_suspicious_target(ip)

    for ip, count in ip_500_count.items():
        if count >= 2:
            findings.append(f"[위험] 500 반복 {count}회 | {ip}")
            risk_score += 15
            warning_count += 1
            add_suspicious_target(ip)

    for ip, count in ip_night_access.items():
        if count >= 3:
            findings.append(f"[주의] 야간 접속 {count}회 | {ip}")
            risk_score += 10
            warning_count += 1
            add_suspicious_target(ip)

    for ip, count in ip_request_count.items():
        if count >= 20:
            findings.append(f"[위험] 과다 요청 {count}회 | {ip}")
            risk_score += 25
            warning_count += 1
            add_suspicious_target(ip)

    risk_score = min(risk_score, MAX_SCORE)

    return {
        "file": selected_file,
        "file_name": os.path.basename(selected_file),
        "log_type": "일반 로그",
        "total_logs": total_logs,
        "login_fail_count": login_fail_count,
        "warning_count": warning_count,
        "risk_score": risk_score,
        "risk_grade": get_grade(risk_score),
        "findings": findings,
        "suspicious_targets": sorted(list(suspicious_targets)),
        "analyzed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }


def analyze_security_csv(file_path):
    global suspicious_targets, target_stats

    total_logs = 0
    login_fail_count = 0
    warning_count = 0
    risk_score = 0
    findings = []

    account_fail_counts = Counter()
    account_lock_counts = Counter()
    event_id_counts = Counter()
    night_login_accounts = Counter()

    # 이벤트 ID별 datetime 저장
    event_time_map = defaultdict(list)

    try:
        with open(file_path, "r", encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)

            for row in reader:
                total_logs += 1

                event_id = str(row.get("Id", "")).strip()
                message = str(row.get("Message", "")).strip()
                time_created = str(row.get("TimeCreated", "")).strip()

                event_id_counts[event_id] += 1

                dt = parse_csv_datetime(time_created)
                if event_id and dt:
                    event_time_map[event_id].append(dt)

                account = normalize_target_name(extract_account_from_message(message))

                if event_id == "4625":  # 로그인 실패
                    login_fail_count += 1

                    if should_exclude_account(account):
                        continue

                    account_fail_counts[account] += 1

                    ensure_target_stats(account)
                    target_stats[account]["type"] = "계정"
                    target_stats[account]["event_4625"] += 1
                    target_stats[account]["login_fail"] += 1

                elif event_id == "4624":  # 로그인 성공
                    if should_exclude_account(account):
                        continue

                    ensure_target_stats(account)
                    target_stats[account]["type"] = "계정"
                    target_stats[account]["event_4624"] += 1

                    if dt and 0 <= dt.hour <= 5:
                        night_login_accounts[account] += 1
                        target_stats[account]["night_access"] += 1

                elif event_id == "4740":  # 계정 잠금
                    if should_exclude_account(account):
                        continue

                    account_lock_counts[account] += 1

                    ensure_target_stats(account)
                    target_stats[account]["type"] = "계정"
                    target_stats[account]["event_4740"] += 1

                else:
                    if should_exclude_account(account):
                        continue

                    ensure_target_stats(account)
                    target_stats[account]["type"] = "계정"
                    target_stats[account]["other_events"] += 1

        for account, count in account_fail_counts.items():
            if count >= 5:
                findings.append(f"[위험] 로그인 실패 {count}회 | {account}")
                risk_score += 20
                warning_count += 1
                add_suspicious_target(account)

        for account, count in account_lock_counts.items():
            if count >= 1:
                findings.append(f"[위험] 계정 잠금 발생 {count}회 | {account}")
                risk_score += 25
                warning_count += 1
                add_suspicious_target(account)

        for account, count in night_login_accounts.items():
            if count >= 3:
                findings.append(f"[주의] 새벽 시간대 로그인 {count}회 | {account}")
                risk_score += 10
                warning_count += 1
                add_suspicious_target(account)

        # 많이 발생한 이벤트 상위 3개 + 정확한 시간 정렬
        top_events = event_id_counts.most_common(3)
        for event_id, count in top_events:
            if event_id:
                findings.append(f"[정보] 이벤트 ID {event_id} 발생 {count}회")

                times = sorted(event_time_map.get(event_id, []))

                if times:
                    findings.append(f"   └ 최초 발생: {format_dt(times[0])}")
                    findings.append(f"   └ 마지막 발생: {format_dt(times[-1])}")
                    findings.append("   └ 최근 발생 시간:")

                    recent_times = times[-5:]
                    for dt_obj in recent_times:
                        findings.append(f"      - {format_dt(dt_obj)}")

        risk_score = min(risk_score, MAX_SCORE)

        return {
            "file": file_path,
            "file_name": os.path.basename(file_path),
            "log_type": "Windows Security CSV",
            "total_logs": total_logs,
            "login_fail_count": login_fail_count,
            "warning_count": warning_count,
            "risk_score": risk_score,
            "risk_grade": get_grade(risk_score),
            "findings": findings,
            "suspicious_targets": sorted(list(suspicious_targets)),
            "analyzed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

    except Exception as e:
        raise e


def apply_analysis_result(result):
    global analysis_result, suspicious_targets

    analysis_result = result
    suspicious_targets = set(result.get("suspicious_targets", []))

    log_message(f"[완료] 로그 형식: {result.get('log_type', '-')}")
    log_message(f"[완료] 총 로그 수: {result['total_logs']}")
    log_message(f"[완료] 로그인 실패 수: {result['login_fail_count']}")
    log_message(f"[완료] 탐지 이벤트 수: {result['warning_count']}")
    log_message(f"[완료] 위험 점수: {result['risk_score']} / {MAX_SCORE}")
    log_message(f"[완료] 위험 등급: {result['risk_grade']}")

    result_box.config(state="normal")
    result_box.delete("1.0", tk.END)
    if result["findings"]:
        for item in result["findings"]:
            result_box.insert(tk.END, item + "\n")
    else:
        result_box.insert(tk.END, "탐지된 이상 행위가 없습니다.\n")
    result_box.config(state="disabled")

    suspicious_box.config(state="normal")
    suspicious_box.delete("1.0", tk.END)
    if result["suspicious_targets"]:
        for target in result["suspicious_targets"]:
            suspicious_box.insert(tk.END, target + "\n")
    else:
        suspicious_box.insert(tk.END, "의심 대상 없음\n")
    suspicious_box.config(state="disabled")

    total_logs_var.set(str(result["total_logs"]))
    fail_count_var.set(str(result["login_fail_count"]))
    warn_count_var.set(str(result["warning_count"]))
    score_var.set(f"{result['risk_score']} / {MAX_SCORE}")
    grade_var.set(result["risk_grade"])
    update_grade_badge(result["risk_grade"])

    set_status(f"분석 완료: {result['analyzed_at']}")


def analyze_log():
    global analysis_result, suspicious_targets, target_stats

    if not selected_file:
        messagebox.showwarning("경고", "먼저 로그 파일을 선택하세요.")
        return

    analysis_result = {}
    suspicious_targets = set()
    target_stats = {}

    output_box.config(state="normal")
    output_box.delete("1.0", tk.END)
    output_box.config(state="disabled")

    result_box.config(state="normal")
    result_box.delete("1.0", tk.END)
    result_box.config(state="disabled")

    suspicious_box.config(state="normal")
    suspicious_box.delete("1.0", tk.END)
    suspicious_box.config(state="disabled")

    log_message("[분석 시작] 로그 분석을 시작합니다.")
    log_message(f"[정보] 제외 컴퓨터 이름: {get_my_computer_name() or '-'}")
    log_message(f"[정보] 제외 사용자 계정: {get_my_username() or '-'}")
    set_status("로그 분석 중...")

    log_type = detect_log_type(selected_file)
    log_message(f"[분석] 감지된 로그 형식: {log_type}")

    try:
        if log_type == "web_log":
            lines = read_text_lines(selected_file)
            result = analyze_web_log(lines)

        elif log_type == "security_csv":
            result = analyze_security_csv(selected_file)

        else:
            messagebox.showwarning("경고", "지원되지 않는 로그 형식입니다.")
            log_message("[오류] 지원되지 않는 로그 형식입니다.")
            set_status("지원되지 않는 로그 형식")
            return

        apply_analysis_result(result)

    except Exception as e:
        messagebox.showerror("오류", f"분석 중 오류 발생:\n{e}")
        log_message(f"[오류] 분석 중 예외 발생: {e}")
        set_status("분석 실패")


def save_txt_report():
    if not analysis_result:
        messagebox.showwarning("경고", "먼저 로그를 분석하세요.")
        return

    save_path = filedialog.asksaveasfilename(
        title="TXT 보고서 저장",
        defaultextension=".txt",
        filetypes=[("Text files", "*.txt")]
    )

    if not save_path:
        return

    try:
        with open(save_path, "w", encoding="utf-8") as f:
            f.write("===== Security Log Analyzer Report =====\n")
            f.write(f"분석 파일: {analysis_result['file']}\n")
            f.write(f"분석 파일명: {analysis_result['file_name']}\n")
            f.write(f"로그 형식: {analysis_result.get('log_type', '-')}\n")
            f.write(f"분석 시간: {analysis_result['analyzed_at']}\n")
            f.write(f"총 로그 수: {analysis_result['total_logs']}\n")
            f.write(f"로그인 실패 수: {analysis_result['login_fail_count']}\n")
            f.write(f"탐지 이벤트 수: {analysis_result['warning_count']}\n")
            f.write(f"위험 점수: {analysis_result['risk_score']} / {MAX_SCORE}\n")
            f.write(f"위험 등급: {analysis_result['risk_grade']}\n")

            f.write("\n[탐지 결과]\n")
            if analysis_result["findings"]:
                for item in analysis_result["findings"]:
                    f.write(f"- {item}\n")
            else:
                f.write("탐지 결과 없음\n")

            f.write("\n[의심 대상 목록]\n")
            if analysis_result["suspicious_targets"]:
                for target in analysis_result["suspicious_targets"]:
                    f.write(f"- {target}\n")
            else:
                f.write("의심 대상 없음\n")

        messagebox.showinfo("저장 완료", f"TXT 보고서가 저장되었습니다.\n{save_path}")
        log_message(f"[TXT 보고서 저장] {save_path}")
        set_status(f"TXT 보고서 저장 완료: {save_path}")

    except Exception as e:
        messagebox.showerror("오류", f"TXT 보고서 저장 실패:\n{e}")
        set_status("TXT 보고서 저장 실패")


def build_html_report():
    if not analysis_result:
        return ""

    grade_color = get_grade_color(analysis_result["risk_grade"])

    findings_html = ""
    if analysis_result["findings"]:
        for item in analysis_result["findings"]:
            findings_html += f"<li>{item}</li>\n"
    else:
        findings_html = "<li>탐지 결과 없음</li>"

    suspicious_html = ""
    if analysis_result["suspicious_targets"]:
        for target in analysis_result["suspicious_targets"]:
            suspicious_html += f"<li>{target}</li>\n"
    else:
        suspicious_html = "<li>의심 대상 없음</li>"

    return f"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<title>Security Log Analyzer Report</title>
<style>
    body {{
        font-family: 'Malgun Gothic', Arial, sans-serif;
        margin: 0;
        padding: 0;
        background: #f4f6f8;
        color: #222;
    }}
    .container {{
        width: 1000px;
        margin: 30px auto;
        background: white;
        border-radius: 14px;
        box-shadow: 0 8px 24px rgba(0,0,0,0.08);
        overflow: hidden;
    }}
    .header {{
        background: #1f2d3d;
        color: white;
        padding: 28px 36px;
    }}
    .header h1 {{
        margin: 0;
        font-size: 34px;
    }}
    .header p {{
        margin: 8px 0 0;
        opacity: 0.9;
    }}
    .section {{
        padding: 24px 36px;
        border-bottom: 1px solid #e9edf2;
    }}
    .section h2 {{
        margin-top: 0;
        color: #1f2d3d;
    }}
    .summary-grid {{
        display: grid;
        grid-template-columns: repeat(5, 1fr);
        gap: 14px;
    }}
    .card {{
        background: #f8fafc;
        border: 1px solid #e5eaf0;
        border-radius: 12px;
        padding: 18px;
        text-align: center;
    }}
    .card-title {{
        font-size: 15px;
        color: #555;
        margin-bottom: 10px;
    }}
    .card-value {{
        font-size: 26px;
        font-weight: bold;
        color: #111;
    }}
    .risk-badge {{
        display: inline-block;
        padding: 8px 16px;
        border-radius: 999px;
        color: white;
        font-weight: bold;
        background: {grade_color};
        margin-top: 8px;
    }}
    ul {{
        margin: 0;
        padding-left: 20px;
        line-height: 1.8;
    }}
    .footer {{
        padding: 20px 36px;
        background: #fafbfc;
        color: #666;
        font-size: 14px;
    }}
</style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Security Log Analyzer Report</h1>
            <p>분석 시간: {analysis_result["analyzed_at"]}</p>
            <p>분석 파일: {analysis_result["file_name"]}</p>
            <p>로그 형식: {analysis_result.get("log_type", "-")}</p>
        </div>

        <div class="section">
            <h2>요약 정보</h2>
            <div class="summary-grid">
                <div class="card">
                    <div class="card-title">총 로그 수</div>
                    <div class="card-value">{analysis_result["total_logs"]}</div>
                </div>
                <div class="card">
                    <div class="card-title">로그인 실패</div>
                    <div class="card-value">{analysis_result["login_fail_count"]}</div>
                </div>
                <div class="card">
                    <div class="card-title">탐지 이벤트</div>
                    <div class="card-value">{analysis_result["warning_count"]}</div>
                </div>
                <div class="card">
                    <div class="card-title">위험 점수</div>
                    <div class="card-value">{analysis_result["risk_score"]} / {MAX_SCORE}</div>
                </div>
                <div class="card">
                    <div class="card-title">위험 등급</div>
                    <div class="card-value">
                        <span class="risk-badge">{analysis_result["risk_grade"]}</span>
                    </div>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>탐지 결과</h2>
            <ul>
                {findings_html}
            </ul>
        </div>

        <div class="section">
            <h2>의심 대상 목록</h2>
            <ul>
                {suspicious_html}
            </ul>
        </div>

        <div class="footer">
            Generated by Security Log Analyzer
        </div>
    </div>
</body>
</html>
"""


def save_html_report():
    if not analysis_result:
        messagebox.showwarning("경고", "먼저 로그를 분석하세요.")
        return

    save_path = filedialog.asksaveasfilename(
        title="HTML 보고서 저장",
        defaultextension=".html",
        filetypes=[("HTML files", "*.html")]
    )

    if not save_path:
        return

    try:
        html_content = build_html_report()
        with open(save_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        messagebox.showinfo("저장 완료", f"HTML 보고서가 저장되었습니다.\n{save_path}")
        log_message(f"[HTML 보고서 저장] {save_path}")
        set_status(f"HTML 보고서 저장 완료: {save_path}")

        open_now = messagebox.askyesno("열기", "저장된 HTML 보고서를 바로 열까요?")
        if open_now:
            webbrowser.open(f"file://{os.path.abspath(save_path)}")

    except Exception as e:
        messagebox.showerror("오류", f"HTML 보고서 저장 실패:\n{e}")
        set_status("HTML 보고서 저장 실패")


def save_report_menu():
    if not analysis_result:
        messagebox.showwarning("경고", "먼저 로그를 분석하세요.")
        return

    report_window = tk.Toplevel(root)
    report_window.title("보고서 형식 선택")
    report_window.geometry("300x170")
    report_window.resizable(False, False)
    report_window.configure(bg="#f4f6f8")
    report_window.transient(root)
    report_window.grab_set()

    tk.Label(
        report_window,
        text="저장할 보고서 형식을 선택하세요",
        font=("맑은 고딕", 11, "bold"),
        bg="#f4f6f8"
    ).pack(pady=(20, 15))

    tk.Button(
        report_window,
        text="TXT 보고서 저장",
        font=("맑은 고딕", 10, "bold"),
        width=18,
        command=lambda: [report_window.destroy(), save_txt_report()]
    ).pack(pady=6)

    tk.Button(
        report_window,
        text="HTML 보고서 저장",
        font=("맑은 고딕", 10, "bold"),
        width=18,
        command=lambda: [report_window.destroy(), save_html_report()]
    ).pack(pady=6)


def show_target_details():
    selected = suspicious_box.get("sel.first", "sel.last").strip() if suspicious_box.tag_ranges("sel") else ""

    if not selected:
        current_text = suspicious_box.get("1.0", tk.END).strip().splitlines()
        if len(current_text) == 1 and current_text[0] == "의심 대상 없음":
            messagebox.showwarning("경고", "표시할 의심 대상이 없습니다.")
            return
        messagebox.showwarning("경고", "의심 대상 목록에서 항목을 드래그해서 선택하세요.")
        return

    target = selected.split()[0]

    if target not in target_stats:
        messagebox.showwarning("경고", "해당 대상의 상세 통계를 찾을 수 없습니다.")
        return

    data = target_stats[target]
    target_type = data.get("type", "대상")

    detail_window = tk.Toplevel(root)
    detail_window.title(f"상세 통계 - {target}")
    detail_window.geometry("460x470")
    detail_window.resizable(False, False)
    detail_window.configure(bg="#f4f6f8")
    detail_window.transient(root)

    tk.Label(
        detail_window,
        text="상세 통계",
        font=("맑은 고딕", 16, "bold"),
        bg="#f4f6f8",
        fg="#1f2d3d"
    ).pack(pady=(20, 8))

    tk.Label(
        detail_window,
        text=f"{target_type}: {target}",
        font=("맑은 고딕", 12, "bold"),
        bg="#f4f6f8",
        fg="#3366cc"
    ).pack(pady=(0, 15))

    info_frame = tk.Frame(detail_window, bg="#ffffff", bd=1, relief="solid")
    info_frame.pack(padx=20, pady=10, fill="both", expand=True)

    rows = [
        ("총 요청 수", data["total_requests"]),
        ("로그인 실패 수", data["login_fail"]),
        ("민감 경로 접근 수", data["admin_access"]),
        ("404 발생 수", data["code_404"]),
        ("500 발생 수", data["code_500"]),
        ("야간 접속 수", data["night_access"]),
        ("이벤트 4624", data["event_4624"]),
        ("이벤트 4625", data["event_4625"]),
        ("이벤트 4740", data["event_4740"]),
        ("기타 이벤트", data["other_events"]),
    ]

    for idx, (label_text, value) in enumerate(rows):
        tk.Label(
            info_frame,
            text=label_text,
            font=("맑은 고딕", 11, "bold"),
            bg="#ffffff",
            anchor="w"
        ).grid(row=idx, column=0, padx=20, pady=8, sticky="w")

        tk.Label(
            info_frame,
            text=str(value),
            font=("맑은 고딕", 11),
            bg="#ffffff",
            fg="#222222",
            anchor="e"
        ).grid(row=idx, column=1, padx=20, pady=8, sticky="e")

    tk.Button(
        detail_window,
        text="닫기",
        font=("맑은 고딕", 10, "bold"),
        width=12,
        command=detail_window.destroy
    ).pack(pady=(0, 18))


def create_sample_log():
    sample_path = filedialog.asksaveasfilename(
        title="샘플 로그 저장",
        defaultextension=".log",
        filetypes=[("Log files", "*.log"), ("Text files", "*.txt")]
    )

    if not sample_path:
        return

    sample_data = """2026-04-06 10:01:12 IP=192.168.0.10 ACTION=LOGIN STATUS=FAIL
2026-04-06 10:01:20 IP=192.168.0.10 ACTION=LOGIN STATUS=FAIL
2026-04-06 10:01:28 IP=192.168.0.10 ACTION=LOGIN STATUS=FAIL
2026-04-06 10:01:35 IP=192.168.0.10 ACTION=LOGIN STATUS=FAIL
2026-04-06 10:01:41 IP=192.168.0.10 ACTION=LOGIN STATUS=FAIL
2026-04-06 10:02:05 IP=203.0.113.7 URL=/admin CODE=404
2026-04-06 10:02:06 IP=203.0.113.7 URL=/admin CODE=404
2026-04-06 10:02:07 IP=203.0.113.7 URL=/admin CODE=404
2026-04-06 02:11:30 IP=198.51.100.4 URL=/login CODE=200
2026-04-06 02:12:00 IP=198.51.100.4 URL=/login CODE=200
2026-04-06 02:13:00 IP=198.51.100.4 URL=/login CODE=200
"""

    try:
        with open(sample_path, "w", encoding="utf-8") as f:
            f.write(sample_data)
        messagebox.showinfo("완료", f"샘플 로그가 저장되었습니다.\n{sample_path}")
        log_message(f"[샘플 로그 생성] {sample_path}")
        set_status(f"샘플 로그 생성 완료: {sample_path}")
    except Exception as e:
        messagebox.showerror("오류", f"샘플 로그 생성 실패:\n{e}")
        set_status("샘플 로그 생성 실패")


root = tk.Tk()
root.title("Security Log Analyzer")
root.geometry("1360x840")
root.configure(bg="#f4f6f8")
root.resizable(False, False)

FONT_TITLE = ("맑은 고딕", 20, "bold")
FONT_SUBTITLE = ("맑은 고딕", 12, "bold")
FONT_MAIN = ("맑은 고딕", 10)
FONT_INFO = ("맑은 고딕", 11, "bold")
FONT_BUTTON = ("맑은 고딕", 10, "bold")

header = tk.Frame(root, bg="#f4f6f8")
header.pack(pady=(15, 5))

tk.Label(
    header,
    text="Security Log Analyzer",
    font=FONT_TITLE,
    bg="#f4f6f8",
    fg="#1f2d3d"
).pack()

button_frame = tk.Frame(root, bg="#f4f6f8")
button_frame.pack(pady=10)

button_style = {
    "font": FONT_BUTTON,
    "width": 15,
    "height": 1,
    "bg": "#ffffff",
    "fg": "#222222",
    "relief": "groove",
    "bd": 2,
    "cursor": "hand2"
}

tk.Button(button_frame, text="로그 파일 선택", command=select_log_file, **button_style).grid(row=0, column=0, padx=6)
tk.Button(button_frame, text="분석 시작", command=analyze_log, **button_style).grid(row=0, column=1, padx=6)
tk.Button(button_frame, text="보고서 저장", command=save_report_menu, **button_style).grid(row=0, column=2, padx=6)
tk.Button(button_frame, text="샘플 로그 생성", command=create_sample_log, **button_style).grid(row=0, column=3, padx=6)
tk.Button(button_frame, text="Security CSV 저장", command=export_security_log_csv, **button_style).grid(row=0, column=4, padx=6)
tk.Button(button_frame, text="초기화", command=clear_output, **button_style).grid(row=0, column=5, padx=6)

file_var = tk.StringVar(value="선택된 파일 없음")
tk.Label(
    root,
    textvariable=file_var,
    font=("맑은 고딕", 10, "underline"),
    fg="#3366cc",
    bg="#f4f6f8"
).pack(pady=(0, 10))

summary_frame = tk.Frame(root, bg="#ffffff", bd=1, relief="solid")
summary_frame.pack(padx=20, pady=5, fill="x")

total_logs_var = tk.StringVar(value="0")
fail_count_var = tk.StringVar(value="0")
warn_count_var = tk.StringVar(value="0")
score_var = tk.StringVar(value=f"0 / {MAX_SCORE}")
grade_var = tk.StringVar(value="-")

tk.Label(summary_frame, text="총 로그 수", font=FONT_INFO, bg="#ffffff", fg="#444444").grid(row=0, column=0, padx=22, pady=(15, 3))
tk.Label(summary_frame, textvariable=total_logs_var, font=("맑은 고딕", 13, "bold"), bg="#ffffff").grid(row=1, column=0, padx=22, pady=(0, 15))

tk.Label(summary_frame, text="로그인 실패", font=FONT_INFO, bg="#ffffff", fg="#444444").grid(row=0, column=1, padx=22, pady=(15, 3))
tk.Label(summary_frame, textvariable=fail_count_var, font=("맑은 고딕", 13, "bold"), bg="#ffffff").grid(row=1, column=1, padx=22, pady=(0, 15))

tk.Label(summary_frame, text="탐지 이벤트", font=FONT_INFO, bg="#ffffff", fg="#444444").grid(row=0, column=2, padx=22, pady=(15, 3))
tk.Label(summary_frame, textvariable=warn_count_var, font=("맑은 고딕", 13, "bold"), bg="#ffffff").grid(row=1, column=2, padx=22, pady=(0, 15))

tk.Label(summary_frame, text="위험 점수", font=FONT_INFO, bg="#ffffff", fg="#444444").grid(row=0, column=3, padx=22, pady=(15, 3))
tk.Label(summary_frame, textvariable=score_var, font=("맑은 고딕", 13, "bold"), bg="#ffffff").grid(row=1, column=3, padx=22, pady=(0, 15))

grade_title_frame = tk.Frame(summary_frame, bg="#ffffff")
grade_title_frame.grid(row=0, column=4, padx=22, pady=(15, 3))
tk.Label(grade_title_frame, text="위험 등급", font=FONT_INFO, bg="#ffffff", fg="#444444").pack(side="left")
badge_canvas = tk.Canvas(grade_title_frame, width=18, height=18, bg="#ffffff", highlightthickness=0)
badge_canvas.pack(side="left", padx=(6, 0))
badge_circle = badge_canvas.create_oval(4, 4, 14, 14, fill="#b0b7c3", outline="#b0b7c3")

grade_value_label = tk.Label(summary_frame, textvariable=grade_var, font=("맑은 고딕", 13, "bold"), bg="#ffffff")
grade_value_label.grid(row=1, column=4, padx=22, pady=(0, 15))

main_frame = tk.Frame(root, bg="#f4f6f8")
main_frame.pack(padx=20, pady=15, fill="both", expand=True)

left_frame = tk.Frame(main_frame, bg="#ffffff", bd=1, relief="solid")
left_frame.grid(row=0, column=0, padx=(0, 10), sticky="n")

center_frame = tk.Frame(main_frame, bg="#ffffff", bd=1, relief="solid")
center_frame.grid(row=0, column=1, padx=(0, 10), sticky="n")

right_frame = tk.Frame(main_frame, bg="#ffffff", bd=1, relief="solid")
right_frame.grid(row=0, column=2, sticky="n")

tk.Label(left_frame, text="실행 로그", font=FONT_SUBTITLE, bg="#eef2f7", fg="#1f2d3d", width=42, pady=8).pack()
output_box = scrolledtext.ScrolledText(
    left_frame,
    width=42,
    height=24,
    font=FONT_MAIN,
    state="disabled",
    wrap="word"
)
output_box.pack(padx=10, pady=(10, 10))

tk.Label(center_frame, text="탐지 결과", font=FONT_SUBTITLE, bg="#eef2f7", fg="#1f2d3d", width=48, pady=8).pack()
result_box = scrolledtext.ScrolledText(
    center_frame,
    width=48,
    height=24,
    font=FONT_MAIN,
    state="disabled",
    wrap="word"
)
result_box.pack(padx=10, pady=(10, 10))

tk.Label(right_frame, text="의심 대상 목록", font=FONT_SUBTITLE, bg="#eef2f7", fg="#1f2d3d", width=26, pady=8).pack()
suspicious_box = scrolledtext.ScrolledText(
    right_frame,
    width=26,
    height=20,
    font=FONT_MAIN,
    state="disabled",
    wrap="word"
)
suspicious_box.pack(padx=10, pady=(10, 10))

tk.Button(
    right_frame,
    text="상세 통계 보기",
    font=("맑은 고딕", 10, "bold"),
    width=22,
    bg="#ffffff",
    relief="groove",
    bd=2,
    cursor="hand2",
    command=show_target_details
).pack(pady=(0, 12))

status_var = tk.StringVar(value="준비 완료")
status_bar = tk.Label(
    root,
    textvariable=status_var,
    font=("맑은 고딕", 9),
    anchor="w",
    bg="#dde3ea",
    fg="#222222",
    padx=10,
    pady=6
)
status_bar.pack(side="bottom", fill="x")

root.mainloop()

<?php
session_start();
require_once '../../login/db.php';

if (!isset($_SESSION['user_id']) || $_SESSION['user_role'] !== 'Client') {
    header("Location: ../../login/index.php");
    exit();
}

$user_id = $_SESSION['user_id'];
$message = "";
$message_type = "success";
$account_deleted = false;

if (isset($_GET['logout'])) {
    session_unset();
    session_destroy();
    header("Location: ../../login/index.php");
    exit();
}

if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['action']) && $_POST['action'] == 'request_booking') {
    $event_name   = htmlspecialchars(trim($_POST['event_name']));
    $event_date   = $_POST['event_date'];
    $venue_id     = intval($_POST['venue_id']);
    $catering     = htmlspecialchars($_POST['catering_tier'] ?? '');
    $equipment    = htmlspecialchars($_POST['equipment_list'] ?? '');
    $total_amount = 500.00;

    if (!empty($user_id) && !empty($event_name) && !empty($event_date) && !empty($venue_id)) {
        try {
            $check_stmt = $pdo->prepare("SELECT COUNT(*) FROM bookings WHERE venue_id = ? AND event_date = ? AND status != 'Cancelled'");
            $check_stmt->execute([$venue_id, $event_date]);
            $is_double_booked = $check_stmt->fetchColumn();

            if ($is_double_booked > 0) {
                $message      = "Conflict: The selected venue is already reserved on this date. Please choose another date.";
                $message_type = "error";
            } else {
                $insert_stmt = $pdo->prepare("INSERT INTO bookings (user_id, venue_id, event_name, event_date, catering_tier, equipment_list, total_amount, deposit_paid, status) VALUES (?, ?, ?, ?, ?, ?, ?, 0, 'Pending')");
                $insert_stmt->execute([$user_id, $venue_id, $event_name, $event_date, $catering, $equipment, $total_amount]);
                $message = "Your booking request has been submitted successfully.";
            }
        } catch (PDOException $e) {
            $message      = "Error processing your booking: " . $e->getMessage();
            $message_type = "error";
        }
    } else {
        $message      = "Please fill in all required fields.";
        $message_type = "error";
    }
}

if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['action']) && $_POST['action'] == 'cancel_booking') {
    $booking_id = intval($_POST['booking_id']);
    try {
        $cancel_stmt = $pdo->prepare("UPDATE bookings SET status = 'Cancelled' WHERE id = ? AND user_id = ?");
        $cancel_stmt->execute([$booking_id, $user_id]);
        if ($cancel_stmt->rowCount() > 0) {
            $message      = "Your reservation has been cancelled.";
            $message_type = "warning";
            if (isset($_GET['view_contract']) && $_GET['view_contract'] == $booking_id) {
                header("Location: cli-dashboard.php");
                exit();
            }
        } else {
            $message      = "Error: Booking not found or unauthorized.";
            $message_type = "error";
        }
    } catch (PDOException $e) {
        $message      = "Error during cancellation: " . $e->getMessage();
        $message_type = "error";
    }
}

if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['action'])) {

    if ($_POST['action'] === 'update_profile') {
        $new_company = htmlspecialchars(trim($_POST['company_name']));
        $new_email   = filter_var(trim($_POST['email']), FILTER_SANITIZE_EMAIL);
        try {
            $stmt = $pdo->prepare("UPDATE users SET company_name=?, email=? WHERE id=?");
            $stmt->execute([$new_company, $new_email, $user_id]);
            $_SESSION['company_name'] = $new_company;
            $message      = "Profile updated successfully.";
            $message_type = "success";
        } catch (PDOException $e) {
            $message      = ($e->getCode() == 23000)
                ? "That email address is already in use by another account."
                : "Error updating profile: " . $e->getMessage();
            $message_type = "error";
        }
    }

    if ($_POST['action'] === 'update_password') {
        $current_pw = $_POST['current_password'] ?? '';
        $new_pw     = $_POST['new_password'] ?? '';
        $confirm_pw = $_POST['confirm_password'] ?? '';
        try {
            $stmt = $pdo->prepare("SELECT password_hash FROM users WHERE id=?");
            $stmt->execute([$user_id]);
            $row = $stmt->fetch();
            if (!password_verify($current_pw, $row['password_hash'])) {
                $message      = "Current password is incorrect.";
                $message_type = "error";
            } elseif (strlen($new_pw) < 8) {
                $message      = "New password must be at least 8 characters.";
                $message_type = "error";
            } elseif ($new_pw !== $confirm_pw) {
                $message      = "New passwords do not match.";
                $message_type = "error";
            } else {
                $hash = password_hash($new_pw, PASSWORD_BCRYPT);
                $stmt = $pdo->prepare("UPDATE users SET password_hash=? WHERE id=?");
                $stmt->execute([$hash, $user_id]);
                $message      = "Password changed successfully.";
                $message_type = "success";
            }
        } catch (PDOException $e) {
            $message      = "Error changing password.";
            $message_type = "error";
        }
    }

    if ($_POST['action'] === 'delete_account') {
        $confirm_pw = $_POST['delete_password'] ?? '';
        try {
            $stmt = $pdo->prepare("SELECT password_hash FROM users WHERE id=?");
            $stmt->execute([$user_id]);
            $row = $stmt->fetch();
            if (!password_verify($confirm_pw, $row['password_hash'])) {
                $message      = "Incorrect password. Account was not deleted.";
                $message_type = "error";
            } else {
                $pdo->prepare("DELETE FROM bookings WHERE user_id=?")->execute([$user_id]);
                $pdo->prepare("DELETE FROM users WHERE id=?")->execute([$user_id]);
                session_unset();
                session_destroy();
                $account_deleted = true;
            }
        } catch (PDOException $e) {
            $message      = "Error deleting account.";
            $message_type = "error";
        }
    }
}

try {
    $venue_stmt = $pdo->query("SELECT * FROM venues ORDER BY id ASC");
    $venues = $venue_stmt->fetchAll();

    $booking_stmt = $pdo->prepare("
        SELECT b.*, v.name as venue_name, v.capacity, v.image_url, v.tier as venue_tier, v.description as venue_description
        FROM bookings b
        INNER JOIN venues v ON b.venue_id = v.id
        WHERE b.user_id = ?
        ORDER BY b.event_date ASC
    ");
    $booking_stmt->execute([$user_id]);
    $my_bookings = $booking_stmt->fetchAll();

    $total_booked = count($my_bookings);
    $pending_rev  = count(array_filter($my_bookings, fn($b) => $b['status'] === 'Pending'));
    $confirmed_ok = count(array_filter($my_bookings, fn($b) => $b['status'] === 'Approved'));
    $unpaid_dep   = count(array_filter($my_bookings, fn($b) => $b['deposit_paid'] == 0 && $b['status'] !== 'Cancelled'));

    $profile_stmt = $pdo->prepare("SELECT company_name, email, created_at FROM users WHERE id=?");
    $profile_stmt->execute([$user_id]);
    $current_user = $profile_stmt->fetch();

} catch (PDOException $e) {
    $venues = [];
    $my_bookings = [];
    $total_booked = $pending_rev = $confirmed_ok = $unpaid_dep = 0;
    $current_user = ['company_name' => $_SESSION['company_name'] ?? '', 'email' => '', 'created_at' => ''];
}

$booked_venue_ids = [];
try {
    $booked_stmt = $pdo->query("SELECT DISTINCT venue_id FROM bookings WHERE status != 'Cancelled' AND event_date >= CURDATE()");
    $booked_venue_ids = $booked_stmt->fetchAll(PDO::FETCH_COLUMN);
} catch (PDOException $e) {
    $booked_venue_ids = [];
}

$active_contract = null;
if (isset($_GET['view_contract'])) {
    $target_booking_id = intval($_GET['view_contract']);
    foreach ($my_bookings as $b) {
        if ($b['id'] == $target_booking_id) {
            $active_contract = $b;
            break;
        }
    }
}

$open_tab = 'venues';
if ($active_contract) {
    $open_tab = 'contract';
} elseif ($_SERVER["REQUEST_METHOD"] === "POST") {
    if (isset($_POST['action']) && in_array($_POST['action'], ['update_profile', 'update_password', 'delete_account'])) {
        $open_tab = 'profile';
    } else {
        $open_tab = 'bookings';
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VenueBook | Client Dashboard</title>
    <link rel="stylesheet" href="cli-style.css">
    <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=EB+Garamond:ital,wght@0,400;0,500;0,600;1,400;1,500&display=swap">
    <style>

        .stat-icon svg, .tab-btn svg, .empty-icon svg {
            width: 20px; height: 20px; fill: currentColor;
            display: inline-block; vertical-align: middle;
        }
        .stat-icon svg { width: 28px; height: 28px; }
        .tab-btn svg { margin-right: 6px; margin-top: -2px; }
        .empty-icon svg { width: 48px; height: 48px; color: #94a3b8; }
        .alert-banner {
            display: flex;
            align-items: center;
            gap: 1rem;
            padding: 1rem 1.5rem;
            border-radius: 12px;
            margin-bottom: 1.5rem;
            font-size: 0.875rem;
            font-weight: 500;
            animation: alertSlideDown 0.4s cubic-bezier(0.16,1,0.3,1) both;
            position: relative;
            overflow: hidden;
        }
        .alert-banner::before {
            content: '';
            position: absolute;
            inset: 0;
            opacity: 0.06;
            background: currentColor;
        }
        .alert-banner--warning {
            background: linear-gradient(135deg, rgba(245,158,11,0.12), rgba(251,191,36,0.06));
            border: 1px solid rgba(245,158,11,0.3);
            color: #92400e;
        }
        .alert-banner--warning .alert-icon-wrap { color: #d97706; }
        .alert-banner--info {
            background: linear-gradient(135deg, rgba(59,130,246,0.10), rgba(96,165,250,0.05));
            border: 1px solid rgba(59,130,246,0.25);
            color: #1e3a8a;
        }
        .alert-banner--info .alert-icon-wrap { color: #3b82f6; }
        .alert-icon-wrap {
            flex-shrink: 0;
            width: 36px; height: 36px;
            border-radius: 8px;
            background: currentColor;
            display: flex; align-items: center; justify-content: center;
        }
        .alert-icon-wrap svg { fill: white; width: 18px; height: 18px; }
        .alert-banner--warning .alert-icon-wrap { background: rgba(217,119,6,0.15); }
        .alert-banner--warning .alert-icon-wrap svg { fill: #d97706; }
        .alert-banner--info .alert-icon-wrap { background: rgba(59,130,246,0.12); }
        .alert-banner--info .alert-icon-wrap svg { fill: #3b82f6; }
        .alert-content { flex: 1; }
        .alert-content strong { display: block; font-weight: 700; margin-bottom: 0.1rem; }
        .alert-content span { opacity: 0.8; font-size: 0.82rem; }
        .alert-cta {
            flex-shrink: 0;
            background: rgba(0,0,0,0.08);
            border: none;
            border-radius: 8px;
            padding: 0.5rem 1rem;
            font-size: 0.78rem;
            font-weight: 700;
            cursor: pointer;
            color: inherit;
            transition: background 0.2s;
            white-space: nowrap;
        }
        .alert-cta:hover { background: rgba(0,0,0,0.14); }
        .alert-dismiss {
            flex-shrink: 0;
            background: none; border: none;
            cursor: pointer; opacity: 0.5;
            padding: 0.25rem; border-radius: 4px;
            transition: opacity 0.2s;
        }
        .alert-dismiss:hover { opacity: 1; }
        .alert-dismiss svg { width: 16px; height: 16px; fill: currentColor; display: block; }
        @keyframes alertSlideDown {
            from { opacity: 0; transform: translateY(-8px); }
            to   { opacity: 1; transform: translateY(0); }
        }

        #toast-root {
            position: fixed; top: 1.5rem; right: 1.75rem;
            z-index: 9999; display: flex; flex-direction: column;
            gap: 0.65rem; pointer-events: none;
        }
        .toast-pill {
            position: relative; overflow: hidden; display: flex;
            align-items: flex-start; gap: 0.85rem;
            background: rgba(255,255,255,0.92);
            border: 1px solid rgba(30,50,100,0.1);
            border-left: 3.5px solid var(--accent);
            border-radius: 14px; padding: 1rem 1.25rem;
            min-width: 290px; max-width: 380px;
            box-shadow: 0 20px 50px rgba(30,50,100,0.14);
            backdrop-filter: blur(20px); pointer-events: auto; cursor: pointer;
            opacity: 0; transform: translateX(20px) scale(0.97);
            animation: toastSlideIn 0.5s cubic-bezier(0.16,1,0.3,1) forwards;
        }
        .toast-pill--error   { border-left-color: var(--danger); }
        .toast-pill--warning { border-left-color: #f59e0b; }
        .toast-pill.toast-leaving { animation: toastSlideOut 0.35s cubic-bezier(0.4,0,1,1) forwards; }
        @keyframes toastSlideIn { to { opacity:1; transform:translateX(0) scale(1); } }
        @keyframes toastSlideOut { to { opacity:0; transform:translateX(16px) scale(0.96); } }
        .toast-icon-wrap {
            flex-shrink:0; width:32px; height:32px; border-radius:8px;
            display:flex; align-items:center; justify-content:center; margin-top:1px;
        }
        .toast-icon-wrap svg { width:16px; height:16px; fill:white; }
        .toast-icon-wrap--success { background: var(--accent); }
        .toast-icon-wrap--error   { background: var(--danger); }
        .toast-icon-wrap--warning { background: #f59e0b; }
        .toast-body { flex: 1; }
        .toast-label { display:block; font-size:0.68rem; font-weight:800; text-transform:uppercase; letter-spacing:0.1em; color:var(--accent); margin-bottom:0.2rem; }
        .toast-label--error   { color: var(--danger); }
        .toast-label--warning { color: #d97706; }
        .toast-message { font-size:0.84rem; line-height:1.45; color:var(--text-primary); }
        .toast-progress { position:absolute; bottom:0; left:0; height:2.5px; width:100%; background:var(--accent); animation:toastBar 4.5s linear forwards; border-radius:0 0 0 14px; }
        .toast-pill--error   .toast-progress { background: var(--danger); }
        .toast-pill--warning .toast-progress { background: #f59e0b; }
        @keyframes toastBar { to { width: 0%; } }

        #deleted-overlay {
            position: fixed; inset: 0; z-index: 99999;
            background: rgba(10,15,30,0.85);
            backdrop-filter: blur(16px);
            display: flex; align-items: center; justify-content: center;
            animation: overlayIn 0.4s ease both;
        }
        @keyframes overlayIn { from { opacity:0; } to { opacity:1; } }
        .deleted-card {
            background: white;
            border-radius: 24px;
            padding: 3rem 2.5rem;
            max-width: 440px; width: 90%;
            text-align: center;
            box-shadow: 0 40px 100px rgba(0,0,0,0.3);
            animation: cardPop 0.5s cubic-bezier(0.16,1,0.3,1) 0.15s both;
        }
        @keyframes cardPop { from { opacity:0; transform:scale(0.88) translateY(20px); } to { opacity:1; transform:scale(1) translateY(0); } }
        .deleted-icon {
            width: 72px; height: 72px; border-radius: 50%;
            background: linear-gradient(135deg, #fee2e2, #fecaca);
            display: flex; align-items: center; justify-content: center;
            margin: 0 auto 1.5rem;
            border: 3px solid #fca5a5;
        }
        .deleted-icon svg { width: 32px; height: 32px; fill: #ef4444; }
        .deleted-card h2 {
            font-size: 1.4rem; font-weight: 800;
            color: #111827; margin-bottom: 0.6rem;
        }
        .deleted-card p {
            font-size: 0.88rem; color: #6b7280;
            line-height: 1.6; margin-bottom: 2rem;
        }
        .deleted-countdown-wrap {
            display: flex; align-items: center; justify-content: center;
            gap: 0.75rem; margin-bottom: 1.5rem;
        }
        .deleted-countdown-ring {
            position: relative; width: 56px; height: 56px; flex-shrink: 0;
        }
        .deleted-countdown-ring svg { transform: rotate(-90deg); }
        .deleted-countdown-ring circle {
            fill: none; stroke-width: 4;
            transition: stroke-dashoffset 1s linear;
        }
        .ring-bg   { stroke: #f3f4f6; }
        .ring-fill { stroke: #ef4444; stroke-linecap: round; }
        .deleted-countdown-num {
            position: absolute; inset: 0;
            display: flex; align-items: center; justify-content: center;
            font-size: 1.1rem; font-weight: 800; color: #ef4444;
        }
        .deleted-countdown-text { font-size: 0.82rem; color: #9ca3af; text-align:left; }
        .deleted-countdown-text strong { display:block; font-size:0.9rem; color:#374151; }
        .deleted-redirect-btn {
            width: 100%;
            background: #111827; color: white;
            border: none; border-radius: 10px;
            padding: 0.875rem; font-size: 0.875rem; font-weight: 700;
            cursor: pointer; transition: background 0.2s;
        }
        .deleted-redirect-btn:hover { background: #1f2937; }

        .profile-layout {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 2rem;
            margin-top: 2rem;
        }
        .profile-card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: var(--radius-md);
            padding: 2rem;
        }
        .profile-card h3 {
            font-size: 1rem; font-weight: 700;
            color: var(--text-primary); margin-bottom: 0.35rem;
        }
        .profile-card .card-desc {
            font-size: 0.82rem; color: var(--text-muted);
            margin-bottom: 1.75rem; padding-bottom: 1.25rem;
            border-bottom: 1px solid var(--border);
        }
        .profile-avatar {
            width: 72px; height: 72px; border-radius: 50%;
            background: var(--accent);
            display: flex; align-items: center; justify-content: center;
            font-size: 1.6rem; font-weight: 700; color: #fff;
            margin-bottom: 1.25rem; flex-shrink: 0;
        }
        .profile-info-row { display: flex; align-items: center; gap: 1.25rem; margin-bottom: 1.5rem; }
        .profile-meta span { display: block; font-size: 0.75rem; color: var(--text-muted); margin-bottom: 0.15rem; }
        .profile-meta strong { font-size: 1rem; color: var(--text-primary); }
        .profile-role-badge {
            display: inline-block;
            background: rgba(16,185,129,0.1); color: #059669;
            border: 1px solid rgba(16,185,129,0.25);
            border-radius: 999px; font-size: 0.68rem; font-weight: 700;
            letter-spacing: 0.08em; text-transform: uppercase;
            padding: 3px 12px; margin-top: 0.4rem;
        }
        .profile-stat-row { display: flex; gap: 1.5rem; padding: 1rem 0; border-top: 1px solid var(--border); margin-top: 0.5rem; }
        .profile-stat span { display: block; font-size: 0.68rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 0.2rem; }
        .profile-stat strong { font-size: 1.05rem; font-weight: 700; color: var(--text-primary); }
        .danger-zone { border-color: rgba(239,68,68,0.25); }
        .danger-zone h3 { color: var(--danger); }
        .danger-zone .card-desc { border-color: rgba(239,68,68,0.15); }
        .danger-warning {
            background: rgba(239,68,68,0.05);
            border: 1px solid rgba(239,68,68,0.15);
            border-radius: 8px; padding: 0.85rem 1rem;
            font-size: 0.82rem; color: var(--danger);
            margin-bottom: 1.25rem; line-height: 1.5;
        }
        .danger-warning strong { display: block; margin-bottom: 0.25rem; }
        @media (max-width: 900px) { .profile-layout { grid-template-columns: 1fr; } }

        #printable-contract-area {
            background: #fdfaf5; color: #1a1208;
            border-radius: var(--radius-md); margin-top: 1.5rem;
            border: 1px solid rgba(0,0,0,0.08);
            font-family: 'EB Garamond', Georgia, serif;
            font-size: 1rem; line-height: 1.75; overflow: hidden;
        }
        .contract-letterhead {
            background: #1a2340; color: white; padding: 2.5rem 3rem 2rem;
            display: flex; align-items: flex-start; justify-content: space-between; gap: 2rem;
        }
        .contract-letterhead-brand h1 { font-family: 'Cinzel', serif; font-size: 1.8rem; font-weight: 600; letter-spacing: 4px; color: white; margin-bottom: 0.2rem; }
        .contract-letterhead-brand h1 span { color: #60a5fa; }
        .contract-letterhead-brand p { font-family: 'Plus Jakarta Sans', sans-serif; font-size: 0.75rem; color: rgba(255,255,255,0.55); letter-spacing: 0.12em; text-transform: uppercase; }
        .contract-letterhead-meta { text-align: right; font-family: 'Plus Jakarta Sans', sans-serif; }
        .contract-letterhead-meta .contract-doc-type { font-size: 0.65rem; text-transform: uppercase; letter-spacing: 0.14em; color: rgba(255,255,255,0.45); margin-bottom: 0.3rem; }
        .contract-letterhead-meta .contract-ref-num { font-size: 1rem; font-weight: 700; color: #60a5fa; letter-spacing: 0.05em; }
        .contract-letterhead-meta .contract-date { font-size: 0.78rem; color: rgba(255,255,255,0.6); margin-top: 0.25rem; }
        .contract-rule-bar { height: 4px; background: linear-gradient(90deg, #b8962e, #e8c84a, #b8962e); }
        .contract-body { padding: 3rem; }
        .contract-title-block { text-align: center; margin-bottom: 2.5rem; padding-bottom: 2rem; border-bottom: 1px solid #d4c9a8; }
        .contract-title-block .contract-doc-label { font-family: 'Plus Jakarta Sans', sans-serif; font-size: 0.68rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.2em; color: #8a7a50; margin-bottom: 0.75rem; }
        .contract-title-block h2 { font-family: 'Cinzel', serif; font-size: 1.6rem; font-weight: 400; letter-spacing: 3px; color: #1a1208; margin-bottom: 0.5rem; line-height: 1.3; }
        .contract-title-block .contract-subtitle { font-size: 0.9rem; color: #6b5e3e; font-style: italic; }
        .contract-parties { margin-bottom: 2rem; padding: 1.5rem 2rem; background: rgba(184,150,46,0.06); border: 1px solid rgba(184,150,46,0.2); border-left: 3px solid #b8962e; border-radius: 4px; }
        .contract-parties p { margin-bottom: 0.6rem; font-size: 1rem; }
        .contract-parties p:last-child { margin-bottom: 0; }
        .contract-parties strong { color: #1a1208; }
        .party-label { font-family: 'Plus Jakarta Sans', sans-serif; font-size: 0.68rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.12em; color: #b8962e; display: inline-block; width: 110px; }
        .contract-section-heading { font-family: 'Plus Jakarta Sans', sans-serif; font-size: 0.7rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.18em; color: #8a7a50; margin: 2rem 0 1rem; padding-bottom: 0.4rem; border-bottom: 1px solid #d4c9a8; }
        .contract-details-table { width: 100%; border-collapse: collapse; margin-bottom: 0.5rem; font-size: 0.97rem; }
        .contract-details-table tr { border-bottom: 1px solid #ede8d8; }
        .contract-details-table tr:last-child { border-bottom: none; }
        .contract-details-table td { padding: 0.65rem 0.5rem; vertical-align: top; }
        .contract-details-table td:first-child { font-family: 'Plus Jakarta Sans', sans-serif; font-size: 0.72rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.1em; color: #8a7a50; width: 200px; padding-right: 1.5rem; white-space: nowrap; }
        .contract-details-table td:last-child { font-weight: 500; color: #1a1208; }
        .contract-amount-highlight { font-size: 1.05rem; font-weight: 600; color: #1a2340; }
        .contract-status-badge { display: inline-block; padding: 0.15rem 0.65rem; border-radius: 3px; font-family: 'Plus Jakarta Sans', sans-serif; font-size: 0.72rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.08em; }
        .contract-status-badge.paid   { background: rgba(5,150,105,0.1); color: #059669; border: 1px solid rgba(5,150,105,0.25); }
        .contract-status-badge.unpaid { background: rgba(225,29,72,0.08); color: #e11d48; border: 1px solid rgba(225,29,72,0.2); }
        .contract-recitals { margin-bottom: 1rem; font-size: 1rem; color: #3d3220; }
        .contract-recitals p { margin-bottom: 0.75rem; text-align: justify; text-indent: 2em; }
        .contract-clauses { counter-reset: clause; list-style: none; padding: 0; margin: 0 0 0.5rem; }
        .contract-clauses li { counter-increment: clause; display: flex; gap: 1rem; margin-bottom: 1rem; font-size: 0.97rem; color: #3d3220; text-align: justify; }
        .contract-clauses li::before { content: counter(clause, upper-roman) "."; font-family: 'Plus Jakarta Sans', sans-serif; font-size: 0.72rem; font-weight: 700; color: #b8962e; min-width: 2rem; padding-top: 0.3rem; text-align: right; flex-shrink: 0; }
        .contract-governing-law { font-size: 0.88rem; color: #6b5e3e; font-style: italic; text-align: center; padding: 1rem; border-top: 1px solid #d4c9a8; border-bottom: 1px solid #d4c9a8; margin: 2rem 0; }
        .contract-signature-block { margin-top: 2.5rem; }
        .contract-signature-intro { font-size: 0.97rem; color: #3d3220; margin-bottom: 2rem; text-align: justify; }
        .contract-signatures-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 3rem; }
        .contract-sig-party .sig-party-label { font-family: 'Plus Jakarta Sans', sans-serif; font-size: 0.65rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.14em; color: #8a7a50; margin-bottom: 2rem; }
        .contract-sig-party .sig-line { border-bottom: 1px solid #1a1208; margin-bottom: 0.5rem; height: 2rem; }
        .contract-sig-party .sig-name-label { font-family: 'Plus Jakarta Sans', sans-serif; font-size: 0.68rem; color: #8a7a50; margin-bottom: 0.2rem; text-transform: uppercase; letter-spacing: 0.08em; }
        .contract-sig-party .sig-name { font-size: 0.97rem; font-weight: 500; color: #1a1208; }
        .contract-sig-party .sig-title { font-family: 'Plus Jakarta Sans', sans-serif; font-size: 0.75rem; color: #8a7a50; font-style: italic; margin-top: 0.1rem; }
        .sig-date-line { margin-top: 1.5rem; }
        .sig-date-line .sig-line { margin-bottom: 0.3rem; }
        .sig-date-line .sig-name-label { margin-bottom: 0; }
        .contract-footer-seal { margin-top: 3rem; padding-top: 2rem; border-top: 2px solid #d4c9a8; display: flex; align-items: center; gap: 2rem; }
        .contract-seal-circle { width: 80px; height: 80px; border-radius: 50%; border: 2px dashed #b8962e; display: flex; align-items: center; justify-content: center; flex-shrink: 0; color: #b8962e; font-family: 'Plus Jakarta Sans', sans-serif; font-size: 0.5rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.1em; text-align: center; line-height: 1.4; padding: 0.5rem; }
        .contract-footer-text { font-size: 0.82rem; color: #8a7a50; font-style: italic; line-height: 1.6; }
        .contract-footer-text strong { color: #6b5e3e; font-style: normal; }
        .contract-actions { display: flex; gap: 1rem; margin-top: 1.5rem; }
    </style>
</head>
<body>

<?php if ($account_deleted): ?>
<div id="deleted-overlay">
    <div class="deleted-card">
        <div class="deleted-icon">
            <svg viewBox="0 0 24 24"><path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/></svg>
        </div>
        <h2>Account Deleted</h2>
        <p>Your account and all associated data have been permanently removed. We're sorry to see you go.</p>
        <div class="deleted-countdown-wrap">
            <div class="deleted-countdown-ring">
                <svg width="56" height="56" viewBox="0 0 56 56">
                    <circle class="ring-bg"   cx="28" cy="28" r="24" />
                    <circle class="ring-fill" cx="28" cy="28" r="24"
                        stroke-dasharray="150.8"
                        stroke-dashoffset="0"
                        id="ring-progress" />
                </svg>
                <div class="deleted-countdown-num" id="countdown-num">8</div>
            </div>
            <div class="deleted-countdown-text">
                <strong>Redirecting shortly</strong>
                You'll be taken to the homepage automatically.
            </div>
        </div>
        <button class="deleted-redirect-btn" onclick="window.location.href='../../login/index.php'">Go Now →</button>
    </div>
</div>
<script>
(function() {
    const TOTAL = 8;
    const circumference = 2 * Math.PI * 24; // 150.796...
    const ring = document.getElementById('ring-progress');
    const num  = document.getElementById('countdown-num');
    ring.style.strokeDasharray  = circumference;
    ring.style.strokeDashoffset = 0;
    let remaining = TOTAL;
    const tick = () => {
        remaining--;
        num.textContent = remaining;
        ring.style.strokeDashoffset = circumference * (1 - remaining / TOTAL);
        if (remaining <= 0) {
            window.location.href = '../../login/index.php';
        }
    };
    // remove CSS transition so JS handles it
    ring.style.transition = 'stroke-dashoffset 1s linear';
    setTimeout(() => { tick(); setInterval(tick, 1000); }, 1000);
})();
</script>
<?php endif; ?>

<nav>
    <div class="nav-brand">
        <h2>venuebook<span>.</span></h2>
        <span class="nav-role-badge">Client</span>
    </div>
    <div class="nav-right">
        <p><?= htmlspecialchars($_SESSION['company_name'] ?? 'Organizer'); ?></p>
        <button class="btn-outline" onclick="switchTab('profile')" style="margin-right:0.5rem;">Profile</button>
        <a href="?logout=true"><button class="btn-outline">Logout</button></a>
    </div>
</nav>

<main>

    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-icon"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M19 3h-1V1h-2v2H8V1H6v2H5c-1.11 0-1.99.9-1.99 2L3 19c0 1.1.89 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm0 16H5V8h14v11zM7 10h5v5H7z"/></svg></div>
            <div><h3>Total Bookings</h3><strong><?= $total_booked; ?></strong></div>
        </div>
        <div class="stat-card stat-warning">
            <div class="stat-icon"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M11.99 2C6.47 2 2 6.48 2 12s4.47 10 9.99 10C17.52 22 22 17.52 22 12S17.52 2 11.99 2zM12 20c-4.42 0-8-3.58-8-8s3.58-8 8-8 8 3.58 8 8-3.58 8-8 8zm.5-13H11v6l5.25 3.15.75-1.23-4.5-2.67z"/></svg></div>
            <div><h3>Pending Review</h3><strong><?= $pending_rev; ?></strong></div>
        </div>
        <div class="stat-card stat-success">
            <div class="stat-icon"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg></div>
            <div><h3>Approved</h3><strong><?= $confirmed_ok; ?></strong></div>
        </div>
        <div class="stat-card stat-danger">
            <div class="stat-icon"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.47 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/></svg></div>
            <div><h3>Awaiting Deposit</h3><strong><?= $unpaid_dep; ?></strong></div>
        </div>
        <div class="stat-card">
            <div class="stat-icon"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M12 7V3H2v18h20V7H12zM6 19H4v-2h2v2zm0-4H4v-2h2v2zm0-4H4V9h2v2zm0-4H4V5h2v2zm4 12H8v-2h2v2zm0-4H8v-2h2v2zm0-4H8V9h2v2zm0-4H8V5h2v2zm10 12h-8v-2h2v-2h-2v-2h2v-2h-2V9h8v10zm-2-8h-2v2h2v-2zm0 4h-2v2h2v-2z"/></svg></div>
            <div><h3>Available Venues</h3><strong><?= count($venues); ?></strong></div>
        </div>
    </div>

    <?php if ($unpaid_dep > 0): ?>
    <div class="alert-banner alert-banner--warning" id="deposit-alert">
        <div class="alert-icon-wrap">
            <svg viewBox="0 0 24 24"><path d="M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z"/></svg>
        </div>
        <div class="alert-content">
            <strong><?= $unpaid_dep; ?> booking<?= $unpaid_dep > 1 ? 's' : ''; ?> awaiting deposit</strong>
            <span>Approved reservations require payment within 7 days to stay confirmed.</span>
        </div>
        <button class="alert-cta" onclick="switchTab('bookings')">Review Now →</button>
        <button class="alert-dismiss" onclick="this.closest('.alert-banner').remove()">
            <svg viewBox="0 0 24 24"><path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/></svg>
        </button>
    </div>
    <?php endif; ?>

    <div class="section-tabs">
        <button class="tab-btn" onclick="switchTab('venues')">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M12 7V3H2v18h20V7H12zM6 19H4v-2h2v2zm0-4H4v-2h2v2zm0-4H4V9h2v2zm0-4H4V5h2v2zm4 12H8v-2h2v2zm0-4H8v-2h2v2zm0-4H8V9h2v2zm0-4H8V5h2v2zm10 12h-8v-2h2v-2h-2v-2h2v-2h-2V9h8v10zm-2-8h-2v2h2v-2zm0 4h-2v2h2v-2z"/></svg> Venues
        </button>
        <button class="tab-btn" onclick="switchTab('bookings')">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M19 3h-4.18C14.4 1.84 13.3 1 12 1c-1.3 0-2.4.84-2.82 2H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm-7 0c.55 0 1 .45 1 1s-.45 1-1 1-1-.45-1-1 .45-1 1-1zm5 16H7v-2h10v2zm0-4H7v-2h10v2zm0-4H7V7h10v2z"/></svg> My Bookings
        </button>
        <button class="tab-btn" onclick="switchTab('contract')">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M14 2H6c-1.1 0-1.99.9-1.99 2L4 20c0 1.1.89 2 1.99 2H18c1.1 0 2-.9 2-2V8l-6-6zm2 16H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z"/></svg> Contract
        </button>
        <button class="tab-btn" onclick="switchTab('profile')">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M12 12c2.7 0 4.8-2.1 4.8-4.8S14.7 2.4 12 2.4 7.2 4.5 7.2 7.2 9.3 12 12 12zm0 2.4c-3.2 0-9.6 1.6-9.6 4.8v2.4h19.2v-2.4c0-3.2-6.4-4.8-9.6-4.8z"/></svg> Profile
        </button>
    </div>

    <div id="tab-venues" class="tab-panel">
        <section>
            <div class="section-head">
                <div>
                    <h2>Available Venues</h2>
                    <p class="section-description">Explore our premium venues available for your next event.</p>
                </div>
            </div>
            <div class="venue-admin-list">
                <?php if (!empty($venues)): ?>
                    <?php foreach ($venues as $venue): ?>
                        <?php $is_booked = in_array($venue['id'], $booked_venue_ids); ?>
                        <div class="venue-admin-card">
                            <img src="<?= htmlspecialchars($venue['image_url']); ?>" alt="<?= htmlspecialchars($venue['name']); ?>">
                            <div class="venue-admin-info">
                                <strong><?= htmlspecialchars($venue['name']); ?></strong>
                                <span class="muted-text"><?= htmlspecialchars($venue['tier'] ?? 'Standard'); ?> &bull; Up to <?= htmlspecialchars($venue['capacity']); ?> guests</span>
                                <p><?= htmlspecialchars($venue['description'] ?? ''); ?></p>
                            </div>
                            <div class="venue-admin-actions">
                                <?php if ($is_booked): ?>
                                    <span class="neon-status status-cancelled" style="text-align:center; display:block; padding:0.5rem;">Unavailable</span>
                                <?php else: ?>
                                    <button class="btn-primary" style="width:100%;" onclick="bookVenue(<?= $venue['id']; ?>)">Select &amp; Book</button>
                                <?php endif; ?>
                            </div>
                        </div>
                    <?php endforeach; ?>
                <?php else: ?>
                    <p class="empty-state">No venues available at the moment.</p>
                <?php endif; ?>
            </div>
        </section>
    </div>

    <div id="tab-bookings" class="tab-panel">
        <div class="workspace-layout">
            <section>
                <div class="section-head">
                    <div>
                        <h2>My Bookings</h2>
                        <p class="section-description">Manage your active reservations and monitor booking status.</p>
                    </div>
                    <div class="filter-row">
                        <select id="status-filter" onchange="filterBookings()">
                            <option value="all">All Statuses</option>
                            <option value="Pending">Pending</option>
                            <option value="Approved">Approved</option>
                            <option value="Cancelled">Cancelled</option>
                        </select>
                    </div>
                </div>
                <div style="overflow-x:auto;">
                    <table id="bookings-table">
                        <thead>
                            <tr><th>#</th><th>Preview</th><th>Venue</th><th>Event</th><th>Date</th><th>Status</th><th>Deposit</th><th>Actions</th></tr>
                        </thead>
                        <tbody>
                            <?php if (!empty($my_bookings)): ?>
                                <?php foreach ($my_bookings as $booking): ?>
                                    <tr data-status="<?= $booking['status']; ?>">
                                        <td class="muted-text">#<?= $booking['id']; ?></td>
                                        <td><img src="<?= htmlspecialchars($booking['image_url']); ?>" class="table-thumb" alt=""></td>
                                        <td><strong><?= htmlspecialchars($booking['venue_name']); ?></strong></td>
                                        <td><?= htmlspecialchars($booking['event_name']); ?></td>
                                        <td><?= htmlspecialchars($booking['event_date']); ?></td>
                                        <td><span class="neon-status status-<?= strtolower($booking['status']); ?>"><?= htmlspecialchars($booking['status']); ?></span></td>
                                        <td>
                                            <?php if ($booking['deposit_paid'] == 1): ?>
                                                <span class="deposit-paid">Paid</span>
                                            <?php else: ?>
                                                <span class="deposit-unpaid">Unpaid</span>
                                            <?php endif; ?>
                                        </td>
                                        <td>
                                            <div class="action-row">
                                                <a href="?view_contract=<?= $booking['id']; ?>"><button class="btn-outline-sm">Contract</button></a>
                                                <?php if ($booking['status'] !== 'Cancelled'): ?>
                                                    <form method="POST" style="margin:0;">
                                                        <input type="hidden" name="action" value="cancel_booking">
                                                        <input type="hidden" name="booking_id" value="<?= $booking['id']; ?>">
                                                        <button type="submit" class="btn-danger-sm">Cancel</button>
                                                    </form>
                                                <?php endif; ?>
                                            </div>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            <?php else: ?>
                                <tr><td colspan="8" class="empty-state">No bookings found.</td></tr>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>
            </section>
            <section>
                <h2>Create Booking</h2>
                <p class="section-description">Submit a new venue reservation request.</p>
                <form method="POST" id="request-form">
                    <input type="hidden" name="action" value="request_booking">
                    <div class="form-group">
                        <label>Event Name</label>
                        <input type="text" name="event_name" placeholder="e.g. Annual Corporate Summit" required>
                    </div>
                    <div class="form-group">
                        <label>Event Date</label>
                        <input type="date" name="event_date" required>
                    </div>
                    <div class="form-group">
                        <label>Select Venue</label>
                        <select name="venue_id" id="venue-select" required>
                            <option value="" disabled selected>Choose a venue</option>
                            <?php foreach ($venues as $venue): ?>
                                <option value="<?= $venue['id']; ?>"><?= htmlspecialchars($venue['name']); ?> (<?= htmlspecialchars($venue['capacity']); ?> guests)</option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <div class="form-row-2">
                        <div class="form-group">
                            <label>Catering Package</label>
                            <select name="catering_tier">
                                <option value="Standard">Standard</option>
                                <option value="Premium">Premium</option>
                                <option value="None">No Catering</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label>Equipment &amp; Add-ons</label>
                            <input type="text" name="equipment_list" placeholder="Projector, LED Wall...">
                        </div>
                    </div>
                    <div style="display:flex; gap:0.75rem;">
                        <button type="submit" class="btn-primary" style="flex:1;">Submit Booking Request</button>
                        <button type="button" class="btn-outline" onclick="document.getElementById('request-form').reset()">Clear</button>
                    </div>
                </form>
            </section>
        </div>
    </div>

    <div id="tab-contract" class="tab-panel">
        <?php if ($active_contract): ?>
            <section id="contract-viewer">
                <h2>Booking Contract</h2>
                <p class="section-description">Official reservation agreement — Reference #VB-<?= $active_contract['id']; ?></p>
                <div id="printable-contract-area">
                    <div class="contract-letterhead">
                        <div class="contract-letterhead-brand">
                            <h1>venue<span>book</span>.</h1>
                            <p>Venue Reservation &amp; Event Services</p>
                        </div>
                        <div class="contract-letterhead-meta">
                            <div class="contract-doc-type">Official Document</div>
                            <div class="contract-ref-num">#VB-<?= htmlspecialchars($active_contract['id']); ?></div>
                            <div class="contract-date">Issued: <?= date('F j, Y'); ?></div>
                        </div>
                    </div>
                    <div class="contract-rule-bar"></div>
                    <div class="contract-body">
                        <div class="contract-title-block">
                            <div class="contract-doc-label">Binding Legal Agreement</div>
                            <h2>Venue Reservation Agreement</h2>
                            <div class="contract-subtitle">This document constitutes a binding contract between the parties named herein.</div>
                        </div>
                        <div class="contract-section-heading">I. Parties to the Agreement</div>
                        <div class="contract-parties">
                            <p><span class="party-label">Service Provider</span><strong>VenueBook Systems Inc.</strong>, a corporation duly organized and existing under the laws of the Republic of the Philippines, hereinafter referred to as the <strong>"Company"</strong>.</p>
                            <p><span class="party-label">Client</span><strong><?= htmlspecialchars($_SESSION['company_name'] ?? 'Client'); ?></strong>, hereinafter referred to as the <strong>"Client"</strong>.</p>
                        </div>
                        <div class="contract-section-heading">II. Recitals</div>
                        <div class="contract-recitals">
                            <p>WHEREAS, the Company is engaged in the business of venue management and event coordination services;</p>
                            <p>WHEREAS, the Client desires to reserve the venue and ancillary services described herein for the purpose of conducting the event specified below;</p>
                            <p>NOW, THEREFORE, in consideration of the mutual covenants and agreements set forth herein, and for other good and valuable consideration, the receipt and sufficiency of which are hereby acknowledged, the parties agree as follows:</p>
                        </div>
                        <div class="contract-section-heading">III. Reservation Details</div>
                        <table class="contract-details-table">
                            <tr><td>Venue</td><td><?= htmlspecialchars($active_contract['venue_name']); ?></td></tr>
                            <tr><td>Event Name</td><td><?= htmlspecialchars($active_contract['event_name']); ?></td></tr>
                            <tr><td>Event Date</td><td><?= date('F j, Y', strtotime($active_contract['event_date'])); ?></td></tr>
                            <tr><td>Catering Package</td><td><?= htmlspecialchars($active_contract['catering_tier'] ?? 'Standard'); ?></td></tr>
                            <tr><td>Equipment &amp; Add-ons</td><td><?= htmlspecialchars($active_contract['equipment_list'] ?: 'None'); ?></td></tr>
                            <tr><td>Booking Status</td><td><span class="neon-status status-<?= strtolower($active_contract['status']); ?>" style="font-family:'Plus Jakarta Sans',sans-serif;"><?= htmlspecialchars($active_contract['status']); ?></span></td></tr>
                        </table>
                        <div class="contract-section-heading">IV. Financial Obligations</div>
                        <table class="contract-details-table">
                            <tr><td>Total Contract Amount</td><td><span class="contract-amount-highlight">₱<?= number_format($active_contract['total_amount'], 2); ?></span></td></tr>
                            <tr><td>Required Deposit (50%)</td><td><span class="contract-amount-highlight">₱<?= number_format($active_contract['total_amount'] * 0.5, 2); ?></span></td></tr>
                            <tr><td>Remaining Balance (50%)</td><td><span class="contract-amount-highlight">₱<?= number_format($active_contract['total_amount'] * 0.5, 2); ?></span></td></tr>
                            <tr><td>Deposit Payment Status</td><td><?php if ($active_contract['deposit_paid']): ?><span class="contract-status-badge paid">&#10003; Deposit Paid</span><?php else: ?><span class="contract-status-badge unpaid">&#9679; Awaiting Payment</span><?php endif; ?></td></tr>
                        </table>
                        <div class="contract-section-heading">V. Terms &amp; Conditions</div>
                        <ol class="contract-clauses">
                            <li>A non-refundable deposit equivalent to fifty percent (50%) of the total contract amount shall be due and payable within seven (7) calendar days from the date of booking confirmation.</li>
                            <li>The remaining balance of fifty percent (50%) shall be due and payable no later than three (3) business days prior to the scheduled event date.</li>
                            <li>Cancellations made less than fourteen (14) calendar days before the event date shall be deemed non-refundable.</li>
                            <li>The Client shall be held solely responsible for any and all damages to the venue caused during the event.</li>
                            <li>The Company reserves the right to cancel any reservation in the event of force majeure.</li>
                            <li>All catering packages and add-on services are subject to availability at the time of booking confirmation.</li>
                            <li>The Client agrees not to sublet or transfer its rights under this Agreement without prior written consent.</li>
                            <li>Any modification to the terms must be made in writing and signed by authorized representatives of both parties.</li>
                        </ol>
                        <div class="contract-governing-law">This Agreement shall be governed by the laws of the <strong>Republic of the Philippines</strong>.</div>
                        <div class="contract-signature-block">
                            <p class="contract-signature-intro">IN WITNESS WHEREOF, the parties hereto have executed this Venue Reservation Agreement as of the date first written above.</p>
                            <div class="contract-signatures-grid">
                                <div class="contract-sig-party">
                                    <div class="sig-party-label">For and on behalf of the Client</div>
                                    <div class="sig-line"></div>
                                    <div class="sig-name-label">Authorized Signature</div>
                                    <div class="sig-name"><?= htmlspecialchars($_SESSION['company_name'] ?? 'Client'); ?></div>
                                    <div class="sig-title">Client / Authorized Representative</div>
                                    <div class="sig-date-line"><div class="sig-line"></div><div class="sig-name-label">Date Signed</div></div>
                                </div>
                                <div class="contract-sig-party">
                                    <div class="sig-party-label">For and on behalf of the Company</div>
                                    <div class="sig-line"></div>
                                    <div class="sig-name-label">Authorized Signature</div>
                                    <div class="sig-name">VenueBook Systems Inc.</div>
                                    <div class="sig-title">Authorized Representative / Coordinator</div>
                                    <div class="sig-date-line"><div class="sig-line"></div><div class="sig-name-label">Date Signed</div></div>
                                </div>
                            </div>
                            <div class="contract-footer-seal">
                                <div class="contract-seal-circle">Official<br>Seal<br>Here</div>
                                <div class="contract-footer-text">
                                    <strong>Document Reference:</strong> #VB-<?= htmlspecialchars($active_contract['id']); ?><br>
                                    Generated electronically by VenueBook on <?= date('F j, Y \a\t g:i A'); ?>.
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="contract-actions">
                    <button onclick="window.print()" class="btn-primary">Print Contract</button>
                    <button type="button" class="btn-outline" onclick="switchTab('bookings')">&larr; Back to Bookings</button>
                </div>
            </section>
        <?php else: ?>
            <section>
                <h2>Contract Viewer</h2>
                <p class="section-description">Go to <strong>My Bookings</strong> and click <strong>Contract</strong> on any booking to load it here.</p>
                <div class="empty-contract-state">
                    <div class="empty-icon"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M14 2H6c-1.1 0-1.99.9-1.99 2L4 20c0 1.1.89 2 1.99 2H18c1.1 0 2-.9 2-2V8l-6-6zm2 16H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z"/></svg></div>
                    <p>No contract selected</p>
                </div>
            </section>
        <?php endif; ?>
    </div>

    <div id="tab-profile" class="tab-panel">
        <section>
            <h2>My Profile</h2>
            <p class="section-description">Manage your account information and security settings.</p>

            <div class="profile-layout">

                <div style="display:flex; flex-direction:column; gap:2rem;">
                    <div class="profile-card">
                        <div class="profile-info-row">
                            <div class="profile-avatar"><?= strtoupper(substr($current_user['company_name'] ?? 'C', 0, 1)); ?></div>
                            <div class="profile-meta">
                                <span>Company / Organization</span>
                                <strong><?= htmlspecialchars($current_user['company_name'] ?? ''); ?></strong>
                                <div class="profile-role-badge">Client</div>
                            </div>
                        </div>
                        <div class="profile-stat-row">
                            <div class="profile-stat">
                                <span>Email</span>
                                <strong><?= htmlspecialchars($current_user['email'] ?? ''); ?></strong>
                            </div>
                            <div class="profile-stat">
                                <span>Member Since</span>
                                <strong><?= date('M j, Y', strtotime($current_user['created_at'] ?? 'now')); ?></strong>
                            </div>
                        </div>
                    </div>

                    <div class="profile-card">
                        <h3>Update Information</h3>
                        <p class="card-desc">Change your company name or email address.</p>
                        <form method="POST">
                            <input type="hidden" name="action" value="update_profile">
                            <div class="form-group">
                                <label>Company Name</label>
                                <input type="text" name="company_name" value="<?= htmlspecialchars($current_user['company_name'] ?? ''); ?>" required>
                            </div>
                            <div class="form-group">
                                <label>Email Address</label>
                                <input type="email" name="email" value="<?= htmlspecialchars($current_user['email'] ?? ''); ?>" required>
                            </div>
                            <button type="submit" class="btn-primary">Save Changes</button>
                        </form>
                    </div>
                </div>

                <div style="display:flex; flex-direction:column; gap:2rem;">

                    <div class="profile-card">
                        <h3>Change Password</h3>
                        <p class="card-desc">Use a strong password of at least 8 characters.</p>
                        <form method="POST">
                            <input type="hidden" name="action" value="update_password">
                            <div class="form-group">
                                <label>Current Password</label>
                                <input type="password" name="current_password" placeholder="Enter current password" required>
                            </div>
                            <div class="form-group">
                                <label>New Password</label>
                                <input type="password" name="new_password" placeholder="At least 8 characters" required>
                            </div>
                            <div class="form-group">
                                <label>Confirm New Password</label>
                                <input type="password" name="confirm_password" placeholder="Repeat new password" required>
                            </div>
                            <button type="submit" class="btn-primary">Update Password</button>
                        </form>
                    </div>

                    <div class="profile-card danger-zone">
                        <h3>Delete Account</h3>
                        <p class="card-desc">Permanently remove your account and all associated data.</p>
                        <div class="danger-warning">
                            <strong>⚠ This action cannot be undone.</strong>
                            Your account, booking history, and all associated data will be permanently deleted.
                        </div>
                        <form method="POST" onsubmit="return confirm('Are you absolutely sure? This will permanently delete your account and cannot be reversed.');">
                            <input type="hidden" name="action" value="delete_account">
                            <div class="form-group">
                                <label>Confirm your password to proceed</label>
                                <input type="password" name="delete_password" placeholder="Enter your password" required>
                            </div>
                            <button type="submit" class="btn-danger-sm" style="width:100%; padding:0.75rem; font-size:0.85rem;">Delete My Account</button>
                        </form>
                    </div>
                </div>

            </div>
        </section>
    </div>

</main>

<div id="toast-root"></div>

<script>
function showToast(message, type = 'success') {
    const root = document.getElementById('toast-root');
    const iconSVGs = {
        success: `<svg viewBox="0 0 24 24"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg>`,
        error:   `<svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/></svg>`,
        warning: `<svg viewBox="0 0 24 24"><path d="M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z"/></svg>`,
    };
    const labels = { success: 'Success', error: 'Error', warning: 'Notice' };
    const pill = document.createElement('div');
    pill.className = `toast-pill${type !== 'success' ? ` toast-pill--${type}` : ''}`;
    pill.innerHTML = `
        <div class="toast-icon-wrap toast-icon-wrap--${type}">${iconSVGs[type] || iconSVGs.success}</div>
        <div class="toast-body">
            <span class="toast-label${type !== 'success' ? ` toast-label--${type}` : ''}">${labels[type] || 'Info'}</span>
            <p class="toast-message">${message}</p>
        </div>
        <div class="toast-progress"></div>`;
    root.appendChild(pill);
    const dismiss = () => { pill.classList.add('toast-leaving'); pill.addEventListener('animationend', () => pill.remove(), { once: true }); };
    pill.addEventListener('click', dismiss);
    setTimeout(dismiss, 4500);
}

<?php if (!empty($message)): ?>
document.addEventListener('DOMContentLoaded', () => {
    showToast(<?= json_encode(strip_tags($message)); ?>, <?= json_encode($message_type); ?>);
});
<?php endif; ?>

function switchTab(tab) {
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach(panel => panel.classList.remove('active'));
    const target = document.getElementById('tab-' + tab);
    if (!target) return;
    target.style.animation = 'none'; target.offsetHeight; target.style.animation = '';
    target.classList.add('active');
    document.querySelectorAll('.tab-btn').forEach(btn => {
        if (btn.getAttribute('onclick') === `switchTab('${tab}')`) btn.classList.add('active');
    });
}

function filterBookings() {
    const val = document.getElementById('status-filter').value;
    document.querySelectorAll('#bookings-table tbody tr').forEach(row => {
        row.style.display = (val === 'all' || row.dataset.status === val) ? '' : 'none';
    });
}

function bookVenue(venueId) {
    switchTab('bookings');
    const select = document.getElementById('venue-select');
    if (select) select.value = venueId;
    setTimeout(() => {
        const form = document.getElementById('request-form');
        if (form) form.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 100);
}

switchTab('<?= $open_tab; ?>');
</script>
</body>
</html>
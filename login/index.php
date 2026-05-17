<?php
session_start();
require_once 'db.php';

$message      = "";
$message_type = "success";
$do_redirect  = false;
$redirect_url = "";

try {
    $stmt   = $pdo->query("SELECT * FROM venues ORDER BY id ASC");
    $venues = $stmt->fetchAll();
} catch (PDOException $e) {
    $venues = [];
    error_log("Database configuration link failure: " . $e->getMessage());
}

if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['action'])) {
    $role     = $_POST['role'] ?? 'Client';
    $email    = filter_var(trim($_POST['email']), FILTER_SANITIZE_EMAIL);
    $password = $_POST['password'] ?? '';

    if ($_POST['action'] == 'register') {
        $company         = htmlspecialchars(trim($_POST['company_name'] ?? ''));
        $hashed_password = password_hash($password, PASSWORD_BCRYPT);

        try {
            $stmt = $pdo->prepare("INSERT INTO users (company_name, email, password_hash, role) VALUES (?, ?, ?, ?)");
            $stmt->execute([$company, $email, $hashed_password, $role]);
            $message      = "Account created successfully. You can now sign in.";
            $message_type = "success";
        } catch (PDOException $e) {
            $message      = ($e->getCode() == 23000)
                ? "This email address is already registered."
                : "An error occurred during registration. Please try again.";
            $message_type = "error";
        }
    }

    elseif ($_POST['action'] == 'login') {
        try {
            $stmt = $pdo->prepare("SELECT * FROM users WHERE email = ?");
            $stmt->execute([$email]);
            $user = $stmt->fetch();

            if ($user && password_verify($password, $user['password_hash'])) {
                if ($user['role'] === $role) {
                    $_SESSION['user_id']      = $user['id'];
                    $_SESSION['user_role']    = $user['role'];
                    $_SESSION['company_name'] = $user['company_name'];

                    $do_redirect  = true;
                    $redirect_url = ($user['role'] === 'Admin')
                        ? '../main/admin/adm-dashboard.php'
                        : '../main/client/cli-dashboard.php';
                } else {
                    $message      = "Access denied: The selected account type does not match your profile.";
                    $message_type = "error";
                }
            } else {
                $message      = "Invalid email or password. Please try again.";
                $message_type = "error";
            }
        } catch (PDOException $e) {
            $message      = "System error. Please try again later.";
            $message_type = "error";
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VenueBook</title>
    <link rel="stylesheet" href="style.css">
    <style>
        /* ── TOAST ───────────────────────────────────────────────── */
        #toast-root {
            position: fixed;
            bottom: 2.5rem;
            right: 2.5rem;
            z-index: 9999;
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
            pointer-events: none;
        }
        .toast-pill {
            position: relative;
            overflow: hidden;
            display: flex;
            align-items: flex-start;
            gap: 1rem;
            background: var(--color-primary);
            color: #fff;
            border: 1px solid rgba(212, 201, 179, 0.2);
            border-radius: var(--radius-pill);
            padding: 1.15rem 1.75rem;
            min-width: 300px;
            max-width: 420px;
            box-shadow: 0 24px 56px rgba(30, 34, 41, 0.25);
            pointer-events: auto;
            cursor: pointer;
            opacity: 0;
            transform: translateY(20px) scale(0.96);
            animation: toastSlideIn 0.6s cubic-bezier(0.16, 1, 0.3, 1) forwards;
        }
        .toast-pill.toast-pill--error { border-color: rgba(248, 113, 113, 0.25); }
        .toast-pill.toast-leaving { animation: toastSlideOut 0.4s cubic-bezier(0.4, 0, 1, 1) forwards; }
        @keyframes toastSlideIn { to { opacity: 1; transform: translateY(0) scale(1); } }
        @keyframes toastSlideOut { to { opacity: 0; transform: translateY(12px) scale(0.95); } }
        .toast-icon { flex-shrink: 0; width: 18px; height: 18px; margin-top: 2px; fill: var(--color-accent); }
        .toast-icon--error { fill: #f87171; }
        .toast-body { flex: 1; }
        .toast-label { display: block; font-family: var(--font-display); font-size: 0.62rem; letter-spacing: 2.5px; text-transform: uppercase; color: var(--color-accent); margin-bottom: 0.25rem; }
        .toast-label--error { color: #f87171; }
        .toast-message { font-family: var(--font-sans); font-size: 0.875rem; line-height: 1.5; color: rgba(255,255,255,0.85); }
        .toast-progress { position: absolute; bottom: 0; left: 0; height: 2px; width: 100%; background: var(--color-accent); animation: toastBar 4.5s linear forwards; }
        .toast-pill--error .toast-progress { background: #f87171; }
        @keyframes toastBar { to { width: 0%; } }

        /* ── LOGIN TRANSITION SCREEN ─────────────────────────────── */
        #vb-login-screen {
            position: fixed;
            inset: 0;
            z-index: 99999;
            background: #0e1628;
            display: flex;
            align-items: center;
            justify-content: center;
            flex-direction: column;
            gap: 0;
            opacity: 0;
            visibility: hidden;
            pointer-events: none;
            transition: opacity 0.35s ease;
        }
        #vb-login-screen.vb-active {
            opacity: 1;
            visibility: visible;
            pointer-events: all;
        }
        #vb-login-screen.vb-exit {
            opacity: 0;
            transition: opacity 0.5s ease;
        }
        #vb-login-particles {
            position: absolute;
            inset: 0;
            width: 100%;
            height: 100%;
            opacity: 0.3;
        }
        .vb-login-inner {
            position: relative;
            z-index: 1;
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 2rem;
        }
        .vb-login-logo-wrap {
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .vb-login-wordmark {
            font-family: var(--font-display, 'Cinzel', serif);
            font-size: 2.6rem;
            font-weight: 700;
            letter-spacing: 0.06em;
            color: #fff;
            text-align: center;
            line-height: 1;
            animation: vbLoginPulse 2.4s ease-in-out infinite;
        }
        .vb-login-wordmark span { color: #b8962e; }
        @keyframes vbLoginPulse {
            0%, 100% { opacity: 1; }
            50%       { opacity: 0.45; }
        }
        .vb-login-greeting {
            font-family: 'EB Garamond', Georgia, serif;
            font-size: 1.1rem;
            font-style: italic;
            color: rgba(255,255,255,0.5);
            text-align: center;
            letter-spacing: 0.02em;
            opacity: 0;
            transform: translateY(6px);
            transition: opacity 0.6s 0.2s ease, transform 0.6s 0.2s ease;
        }
        #vb-login-screen.vb-active .vb-login-greeting {
            opacity: 1;
            transform: translateY(0);
        }
        .vb-login-bar-wrap { width: 180px; }
        .vb-login-bar-track {
            width: 100%;
            height: 1.5px;
            background: rgba(255,255,255,0.07);
            border-radius: 999px;
            overflow: hidden;
        }
        .vb-login-bar-fill {
            height: 100%;
            width: 0%;
            background: linear-gradient(90deg, #b8962e, #e8c84a, #60a5fa);
            border-radius: 999px;
        }
        #vb-login-screen.vb-active .vb-login-bar-fill {
            animation: vbLoginBar 1.8s cubic-bezier(0.4, 0, 0.2, 1) forwards;
        }
        @keyframes vbLoginBar {
            0%   { width: 0%; }
            60%  { width: 72%; }
            85%  { width: 88%; }
            100% { width: 100%; }
        }

        /* ── VENUES FEATURED CARDS (first 3) ─────────────────────── */
        .venues-featured-grid {
            display: flex;
            flex-direction: column;
            gap: 0;
            margin-bottom: 3rem;
        }

        .vfc-card {
            display: grid;
            grid-template-columns: 1fr 1fr;
            border: 1px solid rgba(30, 34, 41, 0.07);
            border-radius: var(--radius-lg);
            overflow: hidden;
            background: var(--card-bg);
            box-shadow: 0 8px 40px rgba(30, 34, 41, 0.04);
            margin-bottom: 2.5rem;
            transition: box-shadow 0.5s cubic-bezier(0.16, 1, 0.3, 1),
                        transform 0.5s cubic-bezier(0.16, 1, 0.3, 1);
        }
        .vfc-card:hover {
            box-shadow: 0 24px 60px rgba(30, 34, 41, 0.09);
            transform: translateY(-4px);
        }

        /* Alternate image side for every 2nd card */
        .vfc-card:nth-child(even) {
            direction: rtl;
        }
        .vfc-card:nth-child(even) > * {
            direction: ltr;
        }

        .vfc-img-wrap {
            position: relative;
            overflow: hidden;
            aspect-ratio: 4 / 3;
        }
        .vfc-img-wrap img {
            width: 100%;
            height: 100%;
            object-fit: cover;
            display: block;
            transition: transform 0.9s cubic-bezier(0.16, 1, 0.3, 1);
        }
        .vfc-card:hover .vfc-img-wrap img {
            transform: scale(1.05);
        }
        .vfc-img-overlay {
            position: absolute;
            inset: 0;
            background: linear-gradient(135deg, rgba(30,34,41,0.18) 0%, transparent 60%);
            pointer-events: none;
        }
        .vfc-tier-badge {
            position: absolute;
            top: 1.5rem;
            left: 1.5rem;
            background: rgba(249, 248, 246, 0.92);
            color: var(--color-primary);
            padding: 5px 16px;
            border-radius: var(--radius-pill);
            font-size: 0.62rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 2px;
            border: 1px solid rgba(30, 34, 41, 0.06);
            backdrop-filter: blur(8px);
            -webkit-backdrop-filter: blur(8px);
        }
        .vfc-card:nth-child(even) .vfc-tier-badge {
            left: auto;
            right: 1.5rem;
        }

        .vfc-body {
            display: flex;
            flex-direction: column;
            justify-content: center;
            padding: 3.5rem 4rem;
        }

        .vfc-index {
            font-family: var(--font-display);
            font-size: 0.6rem;
            font-weight: 600;
            letter-spacing: 3px;
            color: var(--color-accent);
            opacity: 0.9;
            margin-bottom: 1.25rem;
        }

        .vfc-name {
            font-family: var(--font-display);
            font-size: 1.9rem;
            font-weight: 400;
            letter-spacing: 1px;
            color: var(--color-primary);
            line-height: 1.2;
            margin-bottom: 1.5rem;
        }

        .vfc-desc {
            font-family: var(--font-serif);
            font-style: italic;
            font-size: 1.05rem;
            line-height: 1.8;
            color: var(--color-primary);
            opacity: 0.7;
            margin-bottom: 2.5rem;
        }

        .vfc-stats {
            display: flex;
            gap: 3rem;
            border-top: 1px solid rgba(30, 34, 41, 0.06);
            padding-top: 2rem;
        }
        .vfc-stat span {
            display: block;
            font-size: 0.68rem;
            font-weight: 700;
            color: var(--color-muted);
            text-transform: uppercase;
            letter-spacing: 1.5px;
            margin-bottom: 0.35rem;
        }
        .vfc-stat strong {
            font-family: var(--font-display);
            font-size: 1rem;
            font-weight: 400;
            color: var(--color-primary);
            letter-spacing: 0.5px;
        }

        @media (max-width: 820px) {
            .vfc-card,
            .vfc-card:nth-child(even) { grid-template-columns: 1fr; direction: ltr; }
            .vfc-img-wrap { aspect-ratio: 4 / 3; }
            .vfc-card:nth-child(even) .vfc-tier-badge { left: 1.5rem; right: auto; }
            .vfc-body { padding: 2.5rem 2rem; }
        }

        /* ── VENUES ACCORDION (remaining) ────────────────────────── */
        .venues-accordion {
            display: flex;
            flex-direction: column;
            gap: 10px;
        }
        .vac-item {
            border: 1px solid rgba(30, 34, 41, 0.07);
            border-radius: var(--radius-lg);
            overflow: hidden;
            background: var(--card-bg);
            box-shadow: 0 4px 20px rgba(30, 34, 41, 0.02);
            transition: var(--transition-smooth);
        }
        .vac-item:hover {
            box-shadow: 0 8px 32px rgba(30, 34, 41, 0.05);
        }
        .vac-trigger {
            display: flex;
            align-items: center;
            gap: 1.25rem;
            padding: 1.1rem 1.5rem;
            width: 100%;
            text-align: left;
            background: none;
            border: none;
            cursor: pointer;
            color: var(--color-primary);
            font-family: var(--font-sans);
            transition: var(--transition-smooth);
        }
        .vac-trigger:hover {
            background: rgba(30, 34, 41, 0.015);
        }
        .vac-thumb-wrap {
            width: 72px;
            flex-shrink: 0;
            aspect-ratio: 4 / 3;
            border-radius: var(--radius-md);
            overflow: hidden;
        }
        .vac-thumb {
            width: 100%;
            height: 100%;
            object-fit: cover;
            display: block;
            transition: transform 0.6s cubic-bezier(0.16, 1, 0.3, 1);
        }
        .vac-item:hover .vac-thumb {
            transform: scale(1.06);
        }
        .vac-meta { flex: 1; }
        .vac-name {
            font-family: var(--font-display);
            font-size: 1rem;
            font-weight: 400;
            letter-spacing: 0.5px;
            color: var(--color-primary);
            margin: 0 0 5px;
        }
        .vac-sub {
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 0.82rem;
            color: var(--color-muted);
        }
        .vac-badge {
            display: inline-block;
            background: var(--color-bg-light);
            color: var(--color-muted);
            border: 1px solid rgba(30, 34, 41, 0.06);
            padding: 2px 10px;
            border-radius: var(--radius-pill);
            font-size: 0.65rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1.5px;
        }
        .vac-chevron {
            font-size: 1.5rem;
            color: var(--color-muted);
            transition: transform 0.3s cubic-bezier(0.16, 1, 0.3, 1);
            flex-shrink: 0;
            line-height: 1;
        }
        .vac-item.open .vac-chevron {
            transform: rotate(180deg);
        }
        .vac-panel {
            display: flex;
            overflow: hidden;

            max-height: 0;
            opacity: 0;
            transform: translateY(-8px);

            border-top: 0px solid rgba(30, 34, 41, 0.05);

            transition:
                max-height 1s cubic-bezier(0.19, 1, 0.22, 1),
                opacity 0.5s ease-out,
                transform 0.5s ease-out,
                border-top-width 0.2s ease;
        }
        .vac-item.open .vac-panel {
            max-height: 480px;
            opacity: 1;
            transform: translateY(0);

            border-top-width: 1px;
        }
        .vac-panel-img {
            width: 320px;
            flex-shrink: 0;
            aspect-ratio: 4 / 3;
            overflow: hidden;
        }
        .vac-panel-img img {
            width: 100%;
            height: 100%;
            object-fit: cover;
            display: block;
            transform: scale(1.08) translate(1%, 1%);
            transition: transform 0.5s ease;
        }
        .vac-item.open .vac-panel-img img {
            animation: vacKenBurns 8s ease-in-out infinite alternate;
        }
        @keyframes vacKenBurns {
            0%   { transform: scale(1.08) translate(0%,  0%); }
            50%  { transform: scale(1.13) translate(-1.5%, -0.5%); }
            100% { transform: scale(1.08) translate(1%,  0.5%); }
        }
        .vac-panel-body {
            padding: 2rem 2.5rem;
            flex: 1;
            display: flex;
            flex-direction: column;
            justify-content: center;
            opacity: 0;
            transform: translateY(10px);
            transition: opacity 0.45s 0.2s ease, transform 0.45s 0.2s ease;
        }
        .vac-item.open .vac-panel-body {
            opacity: 1;
            transform: translateY(0);
        }
        .vac-panel-body p {
            font-family: var(--font-serif);
            font-style: italic;
            font-size: 1rem;
            color: var(--color-primary);
            opacity: 0.75;
            line-height: 1.75;
            margin: 0 0 1.75rem;
        }
        .vac-stats {
            display: flex;
            gap: 2.5rem;
            border-top: 1px solid rgba(30, 34, 41, 0.05);
            padding-top: 1.5rem;
        }
        .vac-stat span {
            display: block;
            font-size: 0.7rem;
            font-weight: 700;
            color: var(--color-muted);
            text-transform: uppercase;
            letter-spacing: 1.5px;
            margin-bottom: 0.3rem;
        }
        .vac-stat strong {
            font-family: var(--font-display);
            font-size: 1rem;
            font-weight: 400;
            color: var(--color-primary);
            letter-spacing: 0.5px;
        }

        /* Accordion section label */
        .venues-more-label {
            display: flex;
            align-items: center;
            gap: 1.5rem;
            margin-bottom: 1.75rem;
        }
        .venues-more-label span {
            font-size: 0.68rem;
            font-weight: 700;
            letter-spacing: 3px;
            text-transform: uppercase;
            color: var(--color-muted);
            white-space: nowrap;
        }
        .venues-more-label::before,
        .venues-more-label::after {
            content: '';
            flex: 1;
            height: 1px;
            background: rgba(30, 34, 41, 0.08);
        }

        @media (max-width: 640px) {
            .vac-panel { flex-direction: column; }
            .vac-panel-img { width: 100%; aspect-ratio: 16 / 9; }
            .vac-panel-body { padding: 1.5rem; }
        }

        /* ── ETHICS & VALUES ─────────────────────────────────────── */
        .ethics-section { padding-top: 7rem; padding-bottom: 7rem; }
        .ethics-top { margin-bottom: 5rem; }
        .ethics-intro { max-width: 640px; }
        .ethics-eyebrow {
            display: inline-block;
            font-size: 0.7rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 4px;
            color: var(--color-muted);
            margin-bottom: 1.25rem;
        }
        .ethics-intro h2 {
            font-family: var(--font-display);
            font-size: 2.6rem;
            font-weight: 400;
            letter-spacing: 1.5px;
            color: var(--color-primary);
            margin-bottom: 1.5rem;
            line-height: 1.2;
        }
        .ethics-intro p {
            font-family: var(--font-serif);
            font-style: italic;
            font-size: 1.1rem;
            line-height: 1.8;
            color: var(--color-primary);
            opacity: 0.7;
        }
        .ethics-pillars {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 0;
            border: 1px solid var(--glass-border);
            border-radius: var(--radius-lg);
            overflow: hidden;
        }
        .ethics-pillar {
            padding: 2.5rem 2rem;
            border-right: 1px solid var(--glass-border);
            display: flex;
            flex-direction: column;
            gap: 1.5rem;
            transition: background 0.4s ease;
        }
        .ethics-pillar:last-child { border-right: none; }
        .ethics-pillar:hover { background: rgba(30, 34, 41, 0.02); }
        .pillar-num {
            font-family: var(--font-display);
            font-size: 0.65rem;
            font-weight: 600;
            letter-spacing: 3px;
            color: var(--color-accent);
            opacity: 0.8;
        }
        .pillar-body h4 {
            font-family: var(--font-display);
            font-size: 0.9rem;
            font-weight: 400;
            letter-spacing: 0.5px;
            color: var(--color-primary);
            margin-bottom: 1rem;
            line-height: 1.4;
        }
        .pillar-body p {
            font-size: 0.875rem;
            line-height: 1.75;
            color: var(--color-primary);
            opacity: 0.6;
        }
        @media (max-width: 900px) {
            .ethics-pillars { grid-template-columns: repeat(2, 1fr); }
            .ethics-pillar:nth-child(2) { border-right: none; }
            .ethics-pillar:nth-child(1),
            .ethics-pillar:nth-child(2) { border-bottom: 1px solid var(--glass-border); }
        }
        @media (max-width: 560px) {
            .ethics-pillars { grid-template-columns: 1fr; }
            .ethics-pillar { border-right: none; border-bottom: 1px solid var(--glass-border); }
            .ethics-pillar:last-child { border-bottom: none; }
        }
    </style>
</head>
<body>

    <!-- ── LOGIN TRANSITION SCREEN ──────────────────────────────── -->
    <div id="vb-login-screen">
        <canvas id="vb-login-particles"></canvas>
        <div class="vb-login-inner">
            <div class="vb-login-logo-wrap">
                <div class="vb-login-wordmark">venuebook<span>.</span></div>
            </div>
            <p class="vb-login-greeting" id="vb-login-greeting"></p>
            <div class="vb-login-bar-wrap">
                <div class="vb-login-bar-track">
                    <div class="vb-login-bar-fill"></div>
                </div>
            </div>
        </div>
    </div>

    <header class="navbar-container" id="mainNavbar">
        <a href="#explore" class="logo">venuebook<span>.</span></a>
        <nav class="nav-links-wrapper">
            <a href="#explore">explore</a>
            <a href="#venues">venues</a>
            <a href="#about">about</a>
            <a href="#contacts">contacts</a>
        </nav>
        <div class="auth-triggers">
            <button class="nav-btn-link" onclick="openAuthModal('login')">Sign In</button>
            <button class="nav-btn-action" onclick="openAuthModal('register')">Register</button>
        </div>
    </header>

    <div class="hero-wrapper-outer">
        <div class="slideshow-deck" id="slideshowDeck">
            <div class="slide-frame active" data-contrast="dark" style="background-image: url('https://images.unsplash.com/photo-1600585154340-be6161a56a0c?auto=format&fit=crop&w=1800&q=80');"></div>
            <div class="slide-frame" data-contrast="light" style="background-image: url('https://images.unsplash.com/photo-1513694203232-719a280e022f?auto=format&fit=crop&w=1800&q=80');"></div>
            <div class="slide-frame" data-contrast="dark" style="background-image: url('https://images.unsplash.com/photo-1600607687939-ce8a6c25118c?auto=format&fit=crop&w=1800&q=80');"></div>
        </div>
        <section id="explore" class="hero-container">
            <div class="hero-text-content" id="heroTextCard">
                <div class="slogan">Discover Your Perfect Venue</div>
                <h1>spaces that set the <em>form</em> for your events.</h1>
                <p>Streamline corporate event workflows with multi-role access, automatic deposit tracking, and dynamic contract generation.</p>
                <a href="#venues" class="hero-cta">Explore Catalogue</a>
            </div>
        </section>
    </div>

    <!-- ── VENUES SECTION ───────────────────────────────────────── -->
    <section id="venues" class="section-wrapper">
        <div class="section-header">
            <h2>Catalogue of Venues</h2>
            <p style="color: var(--color-muted); margin-top: 0.75rem; font-size: 0.9rem; letter-spacing: 0.5px;">Curated spaces for every occasion</p>
        </div>

        <?php if (!empty($venues)): ?>

            <?php
                $featured  = array_slice($venues, 0, 3);
                $remaining = array_slice($venues, 3);
            ?>

            <!-- ── FEATURED: first 3 venues as expanded cards ── -->
            <div class="venues-featured-grid">
                <?php foreach ($featured as $i => $venue): ?>
                    <div class="vfc-card" id="venue-<?= $i ?>">
                        <div class="vfc-img-wrap">
                            <img src="<?= htmlspecialchars($venue['image_url']) ?>"
                                 alt="<?= htmlspecialchars($venue['name']) ?>">
                            <div class="vfc-img-overlay"></div>
                            <span class="vfc-tier-badge"><?= htmlspecialchars($venue['tier']) ?></span>
                        </div>
                        <div class="vfc-body">
                            <p class="vfc-index">0<?= $i + 1 ?> &mdash; Featured</p>
                            <h3 class="vfc-name"><?= htmlspecialchars($venue['name']) ?></h3>
                            <p class="vfc-desc"><?= htmlspecialchars($venue['description']) ?></p>
                            <div class="vfc-stats">
                                <div class="vfc-stat">
                                    <span>Tier</span>
                                    <strong><?= htmlspecialchars($venue['tier']) ?></strong>
                                </div>
                                <div class="vfc-stat">
                                    <span>Capacity</span>
                                    <strong><?= htmlspecialchars($venue['capacity']) ?> guests</strong>
                                </div>
                            </div>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>

            <!-- ── ACCORDION: remaining venues starting from "The Ivory Pavilion" ── -->
            <?php if (!empty($remaining)): ?>
                <div class="venues-more-label">
                    <span>More Venues</span>
                </div>
                <div class="venues-accordion" id="venuesAccordion">
                    <?php foreach ($remaining as $j => $venue): ?>
                        <?php $i = $j + 3; /* global index offset */ ?>
                        <div class="vac-item" id="vac-item-<?= $j ?>" data-venue-id="venue-<?= $i ?>">
                            <button class="vac-trigger" onclick="toggleVenue(<?= $j ?>)" aria-expanded="false" aria-controls="vac-panel-<?= $j ?>">
                                <div class="vac-thumb-wrap">
                                    <img class="vac-thumb"
                                         src="<?= htmlspecialchars($venue['image_url']) ?>"
                                         alt="<?= htmlspecialchars($venue['name']) ?>">
                                </div>
                                <div class="vac-meta">
                                    <p class="vac-name"><?= htmlspecialchars($venue['name']) ?></p>
                                    <div class="vac-sub">
                                        <span class="vac-badge"><?= htmlspecialchars($venue['tier']) ?></span>
                                        <span>Up to <?= htmlspecialchars($venue['capacity']) ?> guests</span>
                                    </div>
                                </div>
                                <span class="vac-chevron">&#8964;</span>
                            </button>
                            <div class="vac-panel" id="vac-panel-<?= $j ?>" role="region">
                                <div class="vac-panel-img">
                                    <img src="<?= htmlspecialchars($venue['image_url']) ?>"
                                         alt="<?= htmlspecialchars($venue['name']) ?>">
                                </div>
                                <div class="vac-panel-body">
                                    <p><?= htmlspecialchars($venue['description']) ?></p>
                                    <div class="vac-stats">
                                        <div class="vac-stat">
                                            <span>Tier</span>
                                            <strong><?= htmlspecialchars($venue['tier']) ?></strong>
                                        </div>
                                        <div class="vac-stat">
                                            <span>Capacity</span>
                                            <strong><?= htmlspecialchars($venue['capacity']) ?> guests</strong>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>

        <?php else: ?>
            <p style="color: var(--color-muted); text-align: center; padding: 3rem 0;">No venues available at the moment.</p>
        <?php endif; ?>
    </section>

    <section id="about" class="section-wrapper" style="border-top: 1px solid var(--glass-border);">
        <div class="about-split-view">
            <div>
                <h2>We establish the framework for corporate milestones.</h2>
            </div>
            <div>
                <p>We build the foundation behind successful corporate events and executive gatherings. VenueBook streamlines luxury workspace and venue sourcing for international businesses, giving administrative coordinators a centralized system to manage bookings, logistics, and operational requirements with efficiency and confidence.</p>
                <div class="about-metrics-strip">
                    <div class="metric-block"><data>2+</data><label>Years Active</label></div>
                    <div class="metric-block"><data>500+</data><label>Conferences</label></div>
                    <div class="metric-block"><data>96%</data><label>Client Success</label></div>
                    <div class="metric-block"><data>100%</data><label>Quality Check</label></div>
                </div>
            </div>
        </div>
    </section>

    <!-- ── ETHICS & VALUES ──────────────────────────────────────── -->
    <section id="ethics" class="section-wrapper ethics-section" style="border-top: 1px solid var(--glass-border);">
        <div class="ethics-top">
            <div class="ethics-intro">
                <span class="ethics-eyebrow">Our Principles</span>
                <h2>Ethics &amp; Values</h2>
                <p>At VenueBook, we are committed to providing a trusted and professional platform for venue booking and event planning. We believe that strong relationships are built through honesty, respect, and dependable service.</p>
            </div>
        </div>
        <div class="ethics-pillars">
            <div class="ethics-pillar">
                <span class="pillar-num">01</span>
                <div class="pillar-body">
                    <h4>Integrity &amp; Transparency</h4>
                    <p>Venue information is accurate, pricing is transparent, and communication between clients and providers remains clear and professional. Protecting user privacy and maintaining a secure platform are core responsibilities.</p>
                </div>
            </div>
            <div class="ethics-pillar">
                <span class="pillar-num">02</span>
                <div class="pillar-body">
                    <h4>Fairness &amp; Inclusivity</h4>
                    <p>We support fairness, inclusivity, and accessibility by helping different types of venues connect with clients for a wide range of events — treating every user and partner with respect and professionalism.</p>
                </div>
            </div>
            <div class="ethics-pillar">
                <span class="pillar-num">03</span>
                <div class="pillar-body">
                    <h4>Continuous Improvement</h4>
                    <p>We are dedicated to innovation that makes the booking process simpler, faster, and more convenient. Through quality service and responsible practices, VenueBook strives to be a platform people can rely on.</p>
                </div>
            </div>
            <div class="ethics-pillar">
                <span class="pillar-num">04</span>
                <div class="pillar-body">
                    <h4>Responsibility &amp; Trust</h4>
                    <p>We take our role seriously as a bridge between clients and venues. Every interaction, booking, and transaction is handled with care, accountability, and professionalism.</p>
                </div>
            </div>
        </div>
    </section>

    <section id="contacts" class="section-wrapper" style="border-top: 1px solid var(--glass-border);">
        <div class="contacts-card-wrapper">
            <div class="contact-channel">
                <h3>Let's Orchestrate Your Event</h3>
                <p>Reach out to our team to confirm venue availability or discuss custom event requirements.</p>
                <div class="info-row"><label>Hotline Support</label><strong>+7 (495) 120-45-67</strong></div>
                <div class="info-row"><label>Email</label><strong>info@venuebook.corp</strong></div>
            </div>
            <div>
                <form class="contact-minimal-form" onsubmit="event.preventDefault(); showToast('Your inquiry has been submitted. Our team will be in touch shortly.', false);">
                    <div class="inline-form-row">
                        <input type="text" placeholder="Organization Name" class="form-input-field" required>
                        <input type="email" placeholder="Business Email" class="form-input-field" required>
                    </div>
                    <textarea placeholder="Describe your event requirements..." class="form-input-field" style="height:130px; resize:none;" required></textarea>
                    <button type="submit" class="submit-btn" style="width:fit-content; padding:1.1rem 3.5rem;">Submit</button>
                </form>
            </div>
        </div>
    </section>

    <footer class="footer-container">
        <div class="footer-inner">
            <div class="footer-brand">
                <a href="#" class="logo">venuebook<span>.</span></a>
                <p>Premium venue management for corporate events and executive gatherings.</p>
            </div>
            <div class="footer-col">
                <h4>Venues</h4>
                <ul>
                    <?php if (!empty($venues)): ?>
                        <?php foreach ($venues as $i => $v): ?>
                            <li><a href="#venue-<?= $i ?>"><?= htmlspecialchars($v['name']) ?></a></li>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <li><a href="#venues">View Venues</a></li>
                    <?php endif; ?>
                </ul>
            </div>
            <div class="footer-col">
                <h4>Company</h4>
                <ul>
                    <li><a href="#ethics">Ethics &amp; Values</a></li>
                    <li><a href="#about">About Us</a></li>
                    <li><a href="#explore">Solutions</a></li>
                </ul>
            </div>
            <div class="footer-col">
                <h4>Contact</h4>
                <ul>
                    <li><a href="#contacts">Get in Touch</a></li>
                    <li><a href="#contacts">Support</a></li>
                </ul>
            </div>
        </div>
        <div class="footer-copyright">
            <p>&copy; <?= date('Y'); ?> VenueBook Systems Inc. All rights reserved.</p>
            <p>All transactions are securely encrypted.</p>
        </div>
    </footer>

    <!-- AUTH MODAL -->
    <div class="modal-overlay" id="authModal" onclick="closeAuthModal(event)">
        <div class="glass-auth-card" onclick="event.stopPropagation()">
            <button class="modal-close-btn" onclick="closeAuthModal(null, true)">&times;</button>
            <nav class="auth-nav">
                <button type="button" class="auth-nav-btn active" id="tab-login" onclick="switchAuthTab('login')">Sign In</button>
                <button type="button" class="auth-nav-btn" id="tab-register" onclick="switchAuthTab('register')">Register</button>
            </nav>
            <div class="form-wrapper">
                <form action="" method="POST" class="auth-form active" id="form-login">
                    <input type="hidden" name="action" value="login">
                    <div class="input-group">
                        <label>Account Type</label>
                        <div class="role-selector">
                            <input type="radio" name="role" value="Client" id="login-role-client" class="role-option" checked>
                            <label for="login-role-client" class="role-label">Organizer</label>
                            <input type="radio" name="role" value="Admin" id="login-role-admin" class="role-option">
                            <label for="login-role-admin" class="role-label">Coordinator</label>
                        </div>
                    </div>
                    <div class="input-group">
                        <label for="login-email">Email Address</label>
                        <input type="email" id="login-email" name="email" class="input-field" placeholder="name@company.com" required>
                    </div>
                    <div class="input-group">
                        <label for="login-password">Password</label>
                        <input type="password" id="login-password" name="password" class="input-field" placeholder="Enter your password" required>
                    </div>
                    <button type="submit" class="submit-btn">Sign In</button>
                </form>
                <form action="" method="POST" class="auth-form" id="form-register">
                    <input type="hidden" name="action" value="register">
                    <div class="input-group">
                        <label>Register As</label>
                        <div class="role-selector">
                            <input type="radio" name="role" value="Client" id="reg-role-client" class="role-option" checked>
                            <label for="reg-role-client" class="role-label">Organizer</label>
                            <input type="radio" name="role" value="Admin" id="reg-role-admin" class="role-option">
                            <label for="reg-role-admin" class="role-label">Coordinator</label>
                        </div>
                    </div>
                    <div class="input-group">
                        <label for="reg-company">Company Name</label>
                        <input type="text" id="reg-company" name="company_name" class="input-field" placeholder="e.g. Acme Corporation" required>
                    </div>
                    <div class="input-group">
                        <label for="reg-email">Business Email</label>
                        <input type="email" id="reg-email" name="email" class="input-field" placeholder="name@company.com" required>
                    </div>
                    <div class="input-group">
                        <label for="reg-password">Password</label>
                        <input type="password" id="reg-password" name="password" class="input-field" placeholder="Create a strong password" required>
                    </div>
                    <button type="submit" class="submit-btn">Create Account</button>
                </form>
            </div>
        </div>
    </div>

    <!-- TOAST ROOT -->
    <div id="toast-root"></div>

    <script>
        /* ── TOAST ENGINE ────────────────────────────────────────── */
        function showToast(message, isError = false) {
            const root     = document.getElementById('toast-root');
            const iconOk   = `<svg class="toast-icon" viewBox="0 0 24 24"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg>`;
            const iconErr  = `<svg class="toast-icon toast-icon--error" viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/></svg>`;
            const pill     = document.createElement('div');
            pill.className = `toast-pill${isError ? ' toast-pill--error' : ''}`;
            pill.innerHTML = `${isError ? iconErr : iconOk}<div class="toast-body"><span class="toast-label${isError ? ' toast-label--error' : ''}">${isError ? 'Notice' : 'Success'}</span><p class="toast-message">${message}</p></div><div class="toast-progress"></div>`;
            root.appendChild(pill);
            const dismiss = () => { pill.classList.add('toast-leaving'); pill.addEventListener('animationend', () => pill.remove(), { once: true }); };
            pill.addEventListener('click', dismiss);
            setTimeout(dismiss, 4500);
        }

        /* ── LOGIN TRANSITION SCREEN ENGINE ─────────────────────── */
        const loginGreetings = [
            "Welcome back. Your venues await.",
            "Good to have you back.",
            "Preparing your dashboard\u2026",
            "Setting the stage for you.",
            "Loading your workspace.",
            "Your events are in good hands.",
            "Ready when you are.",
            "Stepping into your space\u2026",
        ];

        function launchLoginScreen(redirectUrl) {
            const greetings = loginGreetings;
            document.getElementById('vb-login-greeting').textContent =
                '\u201C' + greetings[Math.floor(Math.random() * greetings.length)] + '\u201D';

            const canvas = document.getElementById('vb-login-particles');
            const ctx    = canvas.getContext('2d');
            canvas.width  = window.innerWidth;
            canvas.height = window.innerHeight;

            const dots = [];
            const count = Math.floor((canvas.width * canvas.height) / 13000);
            for (let i = 0; i < count; i++) {
                dots.push({
                    x:  Math.random() * canvas.width,
                    y:  Math.random() * canvas.height,
                    r:  Math.random() * 1.3 + 0.3,
                    vx: (Math.random() - 0.5) * 0.22,
                    vy: (Math.random() - 0.5) * 0.22,
                    hue: Math.random() > 0.6 ? '43, 80%' : '213, 70%',
                    a:  Math.random() * 0.45 + 0.15,
                });
            }

            let raf;
            function draw() {
                ctx.clearRect(0, 0, canvas.width, canvas.height);
                for (const d of dots) {
                    ctx.beginPath();
                    ctx.arc(d.x, d.y, d.r, 0, Math.PI * 2);
                    ctx.fillStyle = `hsla(${d.hue}, 60%, ${d.a})`;
                    ctx.fill();
                    d.x += d.vx; d.y += d.vy;
                    if (d.x < 0) d.x = canvas.width;
                    if (d.x > canvas.width) d.x = 0;
                    if (d.y < 0) d.y = canvas.height;
                    if (d.y > canvas.height) d.y = 0;
                }
                raf = requestAnimationFrame(draw);
            }
            draw();

            const screen = document.getElementById('vb-login-screen');
            screen.classList.add('vb-active');

            setTimeout(() => {
                cancelAnimationFrame(raf);
                window.location.href = redirectUrl;
            }, 1900);
        }

        /* ── PHP fires login screen if credentials passed ────────── */
        <?php if ($do_redirect): ?>
        document.addEventListener('DOMContentLoaded', () => {
            launchLoginScreen(<?= json_encode($redirect_url); ?>);
        });
        <?php endif; ?>

        /* ── PHP toast for registration / errors ─────────────────── */
        <?php if (!empty($message) && !$do_redirect): ?>
        document.addEventListener('DOMContentLoaded', () => {
            showToast(<?= json_encode(strip_tags($message)); ?>, <?= json_encode($message_type === 'error'); ?>);
            <?php if ($message_type === 'success' && isset($_POST['action']) && $_POST['action'] === 'register'): ?>
            switchAuthTab('login');
            openAuthModal('login');
            <?php elseif ($message_type === 'error'): ?>
            document.getElementById('authModal').classList.add('active');
            switchAuthTab(<?= json_encode($_POST['action'] ?? 'login'); ?>);
            <?php endif; ?>
        });
        <?php endif; ?>

        /* ── VENUES ACCORDION (remaining venues only) ────────────── */
        function toggleVenue(j) {
            const item   = document.getElementById('vac-item-' + j);
            const btn    = item.querySelector('.vac-trigger');
            const isOpen = item.classList.contains('open');

            document.querySelectorAll('.vac-item.open').forEach(el => {
                el.classList.remove('open');
                el.querySelector('.vac-trigger').setAttribute('aria-expanded', 'false');
            });

            if (!isOpen) {
                item.classList.add('open');
                btn.setAttribute('aria-expanded', 'true');
            }
        }

        /* ── FOOTER VENUE LINKS ──────────────────────────────────── */
        document.querySelectorAll('.footer-col a[href^="#venue-"]').forEach(link => {
            link.addEventListener('click', function(e) {
                e.preventDefault();
                const hash = this.getAttribute('href');
                history.pushState(null, '', hash);

                // Featured venues (0-2) — just scroll to card
                const featuredMatch = hash.match(/^#venue-(\d+)$/);
                if (featuredMatch) {
                    const idx = parseInt(featuredMatch[1]);
                    if (idx < 3) {
                        const card = document.getElementById('venue-' + idx);
                        if (card) card.scrollIntoView({ behavior: 'smooth', block: 'center' });
                        return;
                    }
                    // Accordion venues (3+) — open accordion item
                    const j = idx - 3;
                    const item = document.getElementById('vac-item-' + j);
                    if (item) {
                        toggleVenue(j);
                        setTimeout(() => item.scrollIntoView({ behavior: 'smooth', block: 'center' }), 80);
                    }
                }
            });
        });

        /* ── HANDLE DIRECT URL HASH ──────────────────────────────── */
        document.addEventListener('DOMContentLoaded', () => {
            const hash = window.location.hash;
            if (!hash.startsWith('#venue-')) return;
            const match = hash.match(/^#venue-(\d+)$/);
            if (!match) return;
            const idx = parseInt(match[1]);
            setTimeout(() => {
                if (idx < 3) {
                    const card = document.getElementById('venue-' + idx);
                    if (card) card.scrollIntoView({ behavior: 'smooth', block: 'center' });
                } else {
                    const j = idx - 3;
                    const item = document.getElementById('vac-item-' + j);
                    if (item) {
                        toggleVenue(j);
                        setTimeout(() => item.scrollIntoView({ behavior: 'smooth', block: 'center' }), 80);
                    }
                }
            }, 150);
        });

        /* ── SLIDESHOW ───────────────────────────────────────────── */
        const navbar        = document.getElementById('mainNavbar');
        const slideshowDeck = document.getElementById('slideshowDeck');
        const slides        = document.querySelectorAll('.slide-frame');
        const heroTextCard  = document.getElementById('heroTextCard');
        let currentSlideIndex = 0;

        function evaluateContrastEngine() {
            const contrast = slides[currentSlideIndex].getAttribute('data-contrast');
            navbar.classList.toggle('contrast-light-bg', contrast === 'light');
            heroTextCard.classList.toggle('contrast-light-bg', contrast === 'light');
        }
        document.addEventListener('DOMContentLoaded', evaluateContrastEngine);
        function advanceSlideshowLoop() {
            slides[currentSlideIndex].classList.remove('active');
            currentSlideIndex = (currentSlideIndex + 1) % slides.length;
            slides[currentSlideIndex].classList.add('active');
            evaluateContrastEngine();
        }
        setInterval(advanceSlideshowLoop, 5000);

        window.addEventListener('scroll', () => {
            const scrollPos = window.scrollY;
            if (scrollPos > 60) { navbar.classList.add('scrolled'); navbar.classList.remove('contrast-light-bg'); }
            else { navbar.classList.remove('scrolled'); evaluateContrastEngine(); }
            if (scrollPos <= window.innerHeight * 1.2) {
                const translateY    = scrollPos * 0.3;
                const scaleProgress = 1 - (scrollPos / 3000);
                const opacityVal    = 1 - (scrollPos / 700);
                slideshowDeck.style.transform = `translate3d(0, ${translateY}px, 0) scale(${Math.max(0.92, scaleProgress)})`;
                slideshowDeck.style.opacity   = Math.max(0, opacityVal);
            }
        });

        /* ── AUTH MODAL ──────────────────────────────────────────── */
        function openAuthModal(targetTab) {
            document.getElementById('authModal').classList.add('active');
            switchAuthTab(targetTab);
        }
        function closeAuthModal(event = null, force = false) {
            if (force || (event && event.target.classList.contains('modal-overlay'))) {
                document.getElementById('authModal').classList.remove('active');
            }
        }
        window.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && document.getElementById('authModal').classList.contains('active')) closeAuthModal(null, true);
        });
        function switchAuthTab(targetTab) {
            document.querySelectorAll('.auth-nav-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.auth-form').forEach(f => f.classList.remove('active'));
            document.getElementById('tab-' + targetTab).classList.add('active');
            document.getElementById('form-' + targetTab).classList.add('active');
        }
    </script>
</body>
</html>
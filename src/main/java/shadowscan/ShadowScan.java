package shadowscan;

import shadowscan.core.*;
import shadowscan.model.ScanResult;
import shadowscan.providers.*;
import shadowscan.ui.*;
import shadowscan.ui.animations.ResultRevealAnimation;

import java.util.Scanner;
import java.util.concurrent.CompletableFuture;

/**
 * ShadowScan — Terminal Breach Intelligence Tool
 *
 * Main entry point. Wires together the ScanEngine (with all registered
 * BreachProviders), the TerminalRenderer (all visual output), and the
 * AnimationPool (randomized animations per scan).
 *
 * Architecture:
 *   ScanTarget → ScanEngine → BreachProvider (Strategy pattern) → ScanResult
 *   TerminalRenderer handles all display
 *   AnimationPool ensures visual variety across runs
 */
public class ShadowScan {

    private final ScanEngine engine;
    private final TerminalRenderer renderer;
    private final AnimationPool animations;
    private final Scanner scanner;

    public ShadowScan() {
        this.engine = new ScanEngine();
        this.renderer = new TerminalRenderer();
        this.animations = new AnimationPool();
        this.scanner = new Scanner(System.in);

        // Register all providers (Strategy pattern — each wraps a different API)
        engine.registerProvider(new XposedOrNotProvider(engine.getHttpClient()));
        engine.registerProvider(new XposedOrNotPasswordProvider(engine.getHttpClient()));
        engine.registerProvider(new LeakCheckProvider(engine.getHttpClient()));
        engine.registerProvider(new AbuseIpdbProvider(engine.getHttpClient()));
        engine.registerProvider(new AlienVaultDomainProvider(engine.getHttpClient()));
    }

    public void run() {
        // Graceful shutdown on Ctrl+C
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            AnsiPainter.showCursor();
            System.out.println(AnsiPainter.RESET);
        }));

        // Play random intro animation
        ScanAnimation intro = animations.pickIntro();
        intro.play("startup");

        // Main loop
        boolean running = true;
        while (running) {
            animations.getMenuWipe().play("menu");
            renderer.renderMainMenu();
            System.out.print("  " + AnsiPainter.colorize("Select module", AnsiPainter.CYAN) + " "
                    + AnsiPainter.NEON_GREEN + "▸ " + AnsiPainter.RESET);

            String choice = readLine();
            if (choice == null) choice = "0";

            switch (choice.trim()) {
                case "1": handleEmailScan(); break;
                case "2": handlePasswordScan(); break;
                case "3": handleUsernameScan(); break;
                case "4": handlePhoneScan(); break;
                case "5": handleIpScan(); break;
                case "6": handleDomainScan(); break;
                case "0":
                case "exit":
                case "quit":
                    running = false;
                    break;
                default:
                    renderer.renderError("Invalid option. Please select 0-6.");
                    pause();
                    break;
            }
        }

        renderer.renderGoodbye();
    }

    // ─── Module Handlers ───────────────────────────────────────────────

    private void handleEmailScan() {
        renderer.renderModuleHeader("Email Breach Check");
        renderer.renderInputPrompt("Enter email address:");
        String input = readLine();
        if (input == null || input.trim().isEmpty()) return;

        try {
            ScanTarget target = new EmailTarget(input.trim());
            executeScan(target);
        } catch (IllegalArgumentException e) {
            renderer.renderError(e.getMessage());
            pause();
        }
    }

    private void handlePasswordScan() {
        renderer.renderModuleHeader("Password Exposure Check");
        renderer.renderPasswordDisclaimer();
        renderer.renderInputPrompt("Enter password to check:");
        String input = readLine();
        if (input == null || input.isEmpty()) return;

        try {
            ScanTarget target = new PasswordTarget(input);
            executeScan(target);
        } catch (IllegalArgumentException e) {
            renderer.renderError(e.getMessage());
            pause();
        }
    }

    private void handleUsernameScan() {
        renderer.renderModuleHeader("Username Exposure Check");
        renderer.renderInputPrompt("Enter username:");
        String input = readLine();
        if (input == null || input.trim().isEmpty()) return;

        try {
            ScanTarget target = new UsernameTarget(input.trim());
            executeScan(target);
        } catch (IllegalArgumentException e) {
            renderer.renderError(e.getMessage());
            pause();
        }
    }

    private void handlePhoneScan() {
        renderer.renderModuleHeader("Phone Number Exposure Check");
        renderer.renderPhoneDisclaimer();
        renderer.renderInputPrompt("Enter phone number (with country code):");
        String input = readLine();
        if (input == null || input.trim().isEmpty()) return;

        try {
            ScanTarget target = new PhoneTarget(input.trim());
            executeScan(target);
        } catch (IllegalArgumentException e) {
            renderer.renderError(e.getMessage());
            pause();
        }
    }

    private void handleIpScan() {
        renderer.renderModuleHeader("IP Reputation Check");
        renderer.renderIpDisclaimer();
        renderer.renderInputPrompt("Enter IP address:");
        String input = readLine();
        if (input == null || input.trim().isEmpty()) return;

        try {
            ScanTarget target = new IpTarget(input.trim());
            executeScan(target);
        } catch (IllegalArgumentException e) {
            renderer.renderError(e.getMessage());
            pause();
        }
    }

    private void handleDomainScan() {
        renderer.renderModuleHeader("Domain Threat Intelligence");
        renderer.renderInputPrompt("Enter domain name:");
        String input = readLine();
        if (input == null || input.trim().isEmpty()) return;

        try {
            ScanTarget target = new DomainTarget(input.trim());
            executeScan(target);
        } catch (IllegalArgumentException e) {
            renderer.renderError(e.getMessage());
            pause();
        }
    }

    // ─── Scan Execution with Animation ─────────────────────────────────

    private void executeScan(ScanTarget target) {
        System.out.println();

        // New matrix encryption effect right after user submits
        new shadowscan.ui.animations.MatrixProcessingAnimation().play(target.getValue());
        System.out.println();

        // Start the async scan
        CompletableFuture<ScanResult> future = engine.execute(target);

        // Pick a random spinner animation and run it in a separate thread
        ScanAnimation spinner = animations.pickSpinner();
        Thread animThread = new Thread(() -> spinner.play(target.getDisplayLabel()));
        animThread.setDaemon(true);
        animThread.start();

        // Wait for the scan to complete
        ScanResult result;
        try {
            result = future.join();
        } catch (Exception e) {
            result = ScanResult.error("Engine", "Scan failed: " + e.getMessage());
        }

        // Stop the spinner
        animThread.interrupt();
        try {
            animThread.join(500);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        // Clear the spinner line
        AnsiPainter.clearLine();
        System.out.println();

        // Result reveal animation
        ResultRevealAnimation reveal = animations.createResultReveal(result.getRiskLevel());
        reveal.play(result.getRiskLevel().getDisplayName());

        // Render full result
        renderer.renderResult(result);

        // Wait for user
        renderer.renderPressEnter();
        readLine();
    }

    // ─── Utilities ─────────────────────────────────────────────────────

    private String readLine() {
        try {
            if (scanner.hasNextLine()) {
                return scanner.nextLine();
            }
        } catch (Exception e) {
            // Scanner closed or input stream ended
        }
        return null;
    }

    private void pause() {
        renderer.renderPressEnter();
        readLine();
    }

    // ─── Entry Point ───────────────────────────────────────────────────

    public static void main(String[] args) {
        // Enable virtual terminal processing on Windows for ANSI support
        try {
            if (System.getProperty("os.name").toLowerCase().contains("win")) {
                new ProcessBuilder("cmd", "/c", "chcp 65001 > nul").inheritIO().start().waitFor();
            }
        } catch (Exception ignored) {
            // If it fails, ANSI codes may not render — but don't crash
        }

        ShadowScan app = new ShadowScan();
        app.run();
    }
}

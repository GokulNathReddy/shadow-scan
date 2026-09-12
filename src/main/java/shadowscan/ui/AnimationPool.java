package shadowscan.ui;

import shadowscan.ui.animations.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * Animation pool that holds multiple ScanAnimation implementations and
 * randomly selects one per scan execution.
 *
 * NON-NEGOTIABLE REQUIREMENT: No run should look identical to the last one.
 * The pool tracks the last-used animation and avoids repeating it immediately.
 */
public class AnimationPool {

    private final List<ScanAnimation> spinnerAnimations;
    private final List<ScanAnimation> introAnimations;
    private final MenuWipeAnimation menuWipe;
    private final Random rng;
    private int lastSpinnerIndex = -1;
    private int lastIntroIndex = -1;

    public AnimationPool() {
        this.rng = new Random();
        this.menuWipe = new MenuWipeAnimation();

        // Spinner variants — one is randomly picked per scan
        this.spinnerAnimations = new ArrayList<>();
        spinnerAnimations.add(new BrailleSpinnerAnimation());
        spinnerAnimations.add(new RadarSpinnerAnimation());
        spinnerAnimations.add(new GlitchProgressAnimation());
        spinnerAnimations.add(new DataStreamAnimation());

        // Intro animations — one is randomly picked on startup
        this.introAnimations = new ArrayList<>();
        introAnimations.add(new MatrixRainAnimation());
        introAnimations.add(new TypewriterBootAnimation());
    }

    /**
     * Pick a random spinner animation, ensuring it differs from the last one used.
     */
    public ScanAnimation pickSpinner() {
        int index;
        if (spinnerAnimations.size() <= 1) {
            index = 0;
        } else {
            do {
                index = rng.nextInt(spinnerAnimations.size());
            } while (index == lastSpinnerIndex);
        }
        lastSpinnerIndex = index;
        return spinnerAnimations.get(index);
    }

    /**
     * Pick a random intro animation, ensuring it differs from the last one used.
     */
    public ScanAnimation pickIntro() {
        int index;
        if (introAnimations.size() <= 1) {
            index = 0;
        } else {
            do {
                index = rng.nextInt(introAnimations.size());
            } while (index == lastIntroIndex);
        }
        lastIntroIndex = index;
        return introAnimations.get(index);
    }

    /**
     * @return the menu transition wipe animation
     */
    public MenuWipeAnimation getMenuWipe() {
        return menuWipe;
    }

    /**
     * Create a result reveal animation for the given risk level.
     */
    public ResultRevealAnimation createResultReveal(shadowscan.model.RiskLevel riskLevel) {
        return new ResultRevealAnimation(riskLevel);
    }
}

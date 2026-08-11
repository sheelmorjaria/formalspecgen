// Copyright 2026 Sheel Morjaria
// SPDX-License-Identifier: Apache-2.0

/** Canonical sequential JML contract consumed by the traffic-light TLA+ adapter. */
public class TrafficLightController {
    private /*@ spec_public @*/ int ns_light;
    private /*@ spec_public @*/ int ew_light;

    //@ public invariant 0 <= ns_light && ns_light <= 2;
    //@ public invariant 0 <= ew_light && ew_light <= 2;
    //@ public invariant !(ns_light == 2 && ew_light == 2);

    //@ ensures ns_light == 0 && ew_light == 0;
    public TrafficLightController() {
        ns_light = 0;
        ew_light = 0;
    }

    //@ requires ew_light == 0;
    //@ assignable ns_light;
    //@ ensures ns_light == 2;
    public void turnNsGreen() { ns_light = 2; }

    //@ requires ns_light == 2;
    //@ assignable ns_light;
    //@ ensures ns_light == 1;
    public void turnNsYellow() { ns_light = 1; }

    //@ requires ns_light == 1;
    //@ assignable ns_light;
    //@ ensures ns_light == 0;
    public void turnNsRed() { ns_light = 0; }

    //@ requires ns_light == 0;
    //@ assignable ew_light;
    //@ ensures ew_light == 2;
    public void turnEwGreen() { ew_light = 2; }

    //@ requires ew_light == 2;
    //@ assignable ew_light;
    //@ ensures ew_light == 1;
    public void turnEwYellow() { ew_light = 1; }

    //@ requires ew_light == 1;
    //@ assignable ew_light;
    //@ ensures ew_light == 0;
    public void turnEwRed() { ew_light = 0; }
}

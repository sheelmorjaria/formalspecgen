---- MODULE TrafficLightController ----
EXTENDS Naturals

VARIABLES nsLight, ewLight
vars == <<nsLight, ewLight>>

Init == /\ nsLight = 0 /\ ewLight = 0

TurnNsGreen == /\ ewLight = 0 /\ nsLight' = 2 /\ UNCHANGED ewLight
TurnNsYellow == /\ nsLight = 2 /\ nsLight' = 1 /\ UNCHANGED ewLight
TurnNsRed == /\ nsLight = 1 /\ nsLight' = 0 /\ UNCHANGED ewLight
TurnEwGreen == /\ nsLight = 0 /\ ewLight' = 2 /\ UNCHANGED nsLight
TurnEwYellow == /\ ewLight = 2 /\ ewLight' = 1 /\ UNCHANGED nsLight
TurnEwRed == /\ ewLight = 1 /\ ewLight' = 0 /\ UNCHANGED nsLight

Next ==
    \/ TurnNsGreen
    \/ TurnNsYellow
    \/ TurnNsRed
    \/ TurnEwGreen
    \/ TurnEwYellow
    \/ TurnEwRed

TypeOK == /\ nsLight \in 0..2 /\ ewLight \in 0..2
NoSimultaneousGreenLights == ~(nsLight = 2 /\ ewLight = 2)
Spec == Init /\ [][Next]_vars
====
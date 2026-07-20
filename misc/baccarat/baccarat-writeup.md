# OmniCTF 2026 Quals - Baccarat Write-Up - Misc

Description: The goal is to learn which side is favored for each visible matchup, then size even-money bets well enough to grow the bankroll to the target.

## Solution
The goal is to get 100k from 1k. The strategy is to precompute win rates for every matchup between player and banker via simulations, and bet on whichever side has the higher probability.

| Player | Banker | Bet | Win% |
| --- | --- | --- | --- |
| OmniCybr | BlackShard | Player | 57.7% |
| BlackShard | OmniCybr | Banker | 56.0% |
| NorthStar | BlackShard | Player | 57.1% |
| BlackShard | NorthStar | Banker | 57.4% |
| NipCat | BlackShard | Player | 56.2% |
| BlackShard | NipCat | Banker | 55.5% |
| VoltaicAI | BlackShard | Player | 54.9% |
| BlackShard | VoltaicAI | Banker | 52.5% |
| OmniCybr | VoltaicAI | Player | 52.8% |
| VoltaicAI | OmniCybr | Banker | 52.3% |
| NorthStar | VoltaicAI | Player | 52.1% |
| VoltaicAI | NorthStar | Banker | 52.6% |

Then we write [script.py](script.py) for automation.

**Flag: Omni{baccarat_kelly_goes_brrrr_6da7b1f}**

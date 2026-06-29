# Quantum-Resistant Inline Retrofittable Authentication (QIRA)
QIRA is a novel crypto-agile quantum-resistant authentication and authenticated encryption framework.
The framework safeguards the confidentiality, authenticity, integrity, and non-repudiation of industrial network communication using a bump-in-the-wire approach.
In particular, we tailored QIRA to the strict timing constraints inherent to the protocols employed in digital substations of smart grids, especially the protocols GOOSE and SV.
As QIRA features a novel bypass-capable architecture, it facilitates deployment via retrofitting of existing substations, and allows adaption to partially incompatible environments via configurable fine-grained bypassing of network streams.

## Performance Analysis
### Run Analysis
To reconduct the performance analysis you require five independent computers, we used five [Raspberry Pi 5 8GB](https://www.raspberrypi.com/products/raspberry-pi-5), interconnected via Ethernet.
Regarding the commands to be executed to run the analysis, please refer to the performance analysis targets "performance_analysis_*" within the [Makefile](https://github.com/gstuer/QIRA/tree/main/Makefile) for further information.

### Results
You can find the latest results of the performance analysis [here](https://github.com/gstuer/QIRA/tree/main/evaluation/rtt-estimation/results/qira-pre).
Each run of the performance analysis is represented by a result file in the JSON format.
#### Result File Layout
```json
{
  "label": "Label used to identify analysis run (typically DEM algorithm)",
  "lost": "Number of lost packets",
  "pps": "Number of sequential packets per second",
  "mean": "Mean RTT in ms",
  "median": "Median RTT in ms",
  "standardDeviation": "Standard deviation of the RTT in ms",
  "max": "Max RTT in ms",
  "min": "Min RTT in ms",
  "minMaxMidrange": "Non-trimmed central value between max and min RTT",
  "minMaxRange": "Difference of max and min RTT",
  "lowLatencyReadings": "Number of readings with RTT ≤ 6 ms",
  "mediumLatencyReadings": "Number of readings with RTT ≤ 40 ms",
  "highLatencyReadings": "Number of readings with RTT ≤ 200 ms",
  "veryHighLatencyReadings": "Number of readings with RTT ≤ 1000 ms",
  "roundTripTimes": "Time-ordered array of raw RTT readings"
}
```

## Publications
- Moritz Gstür, Mohammed Ramadan, and Veit Hagenmeyer. 2026. Quantum-Resistant Crypto-Agile Inline Authentication and Encryption Framework for IEC 61850 Digital Substations. In Proceedings of the 2026 ACM Sustainability Week (ACM Sustainability Week '26). Association for Computing Machinery, New York, NY, USA, 1–8. doi:[10.1145/3765611.3815134](https://doi.org/10.1145/3765611.3815134)

- More are already in progress...

## License
This project is licensed under the **European Union Public License 1.2**. See the LICENSE file for more details.

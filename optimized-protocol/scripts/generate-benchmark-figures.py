#!/usr/bin/env python3
"""Generate the paper figures from the final GovBind benchmark sessions."""

from __future__ import annotations

import argparse
import json
import math
import os
import shlex
import statistics
import tempfile
from pathlib import Path
from typing import Callable, Sequence

# Keep Matplotlib's cache out of the home directory on restricted machines.
_MPL_CACHE = Path(tempfile.gettempdir()) / "govbind-matplotlib"
_MPL_CACHE.mkdir(parents=True, exist_ok=True)
os.environ.setdefault("MPLCONFIGDIR", str(_MPL_CACHE))
os.environ.setdefault("XDG_CACHE_HOME", str(_MPL_CACHE))

import matplotlib  # noqa: E402

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.lines import Line2D  # noqa: E402
from matplotlib.patches import Patch  # noqa: E402


SCRIPT_DIR = Path(__file__).resolve().parent
VERSION_2_DIR = SCRIPT_DIR.parent
WORKSPACE_DIR = VERSION_2_DIR.parent.parent

DEFAULT_INPUT = VERSION_2_DIR / "benchmarks.json"
DEFAULT_OUTPUT_DIR = WORKSPACE_DIR / "paper" / "figures"

PROFILE_ORDER = ("tax-debt", "driver-license", "residence")
PROFILE_LABELS = {
    "tax-debt": "Tax debt",
    "driver-license": "Traffic penalties",
    "residence": "Residence city",
}

ZKTLS_COLOR = "#0072B2"
NOIR_COLOR = "#D55E00"
COLD_COLOR = "#CC79A7"
WARM_COLOR = "#009E73"
DOCUMENT_MARKERS = {"A": "o", "B": "^"}

# Two-sided 95% Student-t critical values, indexed by degrees of freedom.
T_CRITICAL_95 = {
    1: 12.706,
    2: 4.303,
    3: 3.182,
    4: 2.776,
    5: 2.571,
    6: 2.447,
    7: 2.365,
    8: 2.306,
    9: 2.262,
    10: 2.228,
    11: 2.201,
    12: 2.179,
    13: 2.160,
    14: 2.145,
    15: 2.131,
    16: 2.120,
    17: 2.110,
    18: 2.101,
    19: 2.093,
    20: 2.086,
    21: 2.080,
    22: 2.074,
    23: 2.069,
    24: 2.064,
    25: 2.060,
    26: 2.056,
    27: 2.052,
    28: 2.048,
    29: 2.045,
    30: 2.042,
}


def arithmetic_mean(values: Sequence[float]) -> float:
    if not values:
        raise ValueError("cannot average an empty sequence")
    return statistics.fmean(values)


def mean_ci95(values: Sequence[float]) -> tuple[float, float]:
    """Return the mean and 95% Student-t half-width."""
    mean = arithmetic_mean(values)
    if len(values) < 2:
        return mean, 0.0
    degrees_of_freedom = len(values) - 1
    critical = T_CRITICAL_95.get(degrees_of_freedom, 1.960)
    half_width = critical * statistics.stdev(values) / math.sqrt(len(values))
    return mean, half_width


def pdf_argument(command: str) -> str:
    arguments = shlex.split(command)
    try:
        index = arguments.index("--pdf")
        return arguments[index + 1]
    except (ValueError, IndexError) as error:
        raise ValueError("benchmark command has no usable --pdf argument") from error


def require_number(container: dict, key: str, context: str) -> float:
    value = container.get(key)
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ValueError(f"{context}.{key} must be numeric")
    return float(value)


def load_sessions(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8") as benchmark_file:
        records = json.load(benchmark_file)

    if not isinstance(records, list):
        raise ValueError("benchmark file must contain a JSON array")

    sessions = [
        record
        for record in records
        if record.get("status") == "complete"
        and record.get("configuration", {}).get("profile") in PROFILE_ORDER
    ]

    counts = {
        profile: sum(
            session["configuration"]["profile"] == profile for session in sessions
        )
        for profile in PROFILE_ORDER
    }
    if any(count != 8 for count in counts.values()) or len(sessions) != 24:
        raise ValueError(
            "expected exactly 24 final sessions (8 for each evaluated profile); "
            f"found {counts}"
        )

    for session_index, session in enumerate(sessions, start=1):
        configuration = session.get("configuration", {})
        context = f"session {session_index}"
        if configuration.get("runs") != 3:
            raise ValueError(f"{context} must configure exactly 3 proof runs")
        if configuration.get("verificationRunsPerProof") != 10:
            raise ValueError(f"{context} must configure 10 verification runs")
        if not isinstance(configuration.get("command"), str):
            raise ValueError(f"{context} has no benchmark command")

        runs = session.get("runs")
        if not isinstance(runs, list) or len(runs) != 3:
            raise ValueError(f"{context} must contain exactly 3 completed runs")

        for run_index, run in enumerate(runs, start=1):
            run_context = f"{context}, run {run_index}"
            generation = run.get("generation", {})
            for key in (
                "zkTlsMs",
                "noirTotalMs",
                "totalMs",
                "zkTlsPeakRssBytes",
                "noirPeakRssBytes",
            ):
                require_number(generation, key, f"{run_context}.generation")

            verifications = run.get("verification")
            if not isinstance(verifications, list) or len(verifications) != 10:
                raise ValueError(
                    f"{run_context} must contain exactly 10 verification measurements"
                )
            for verification_index, verification in enumerate(verifications, start=1):
                require_number(
                    verification,
                    "totalMs",
                    f"{run_context}.verification[{verification_index}]",
                )

            sizes = run.get("sizes", {})
            for key in (
                "responseBodyBytes",
                "compressedStreamBytes",
                "presentationBytes",
                "proofBytes",
                "publicInputsBytes",
            ):
                require_number(sizes, key, f"{run_context}.sizes")
            private_ranges = sizes.get("privateRanges")
            if not isinstance(private_ranges, list) or not private_ranges:
                raise ValueError(f"{run_context}.sizes.privateRanges must be non-empty")
            for range_index, private_range in enumerate(private_ranges, start=1):
                require_number(
                    private_range,
                    "length",
                    f"{run_context}.sizes.privateRanges[{range_index}]",
                )

        session["_document_path"] = pdf_argument(configuration["command"])

    # Use anonymized, stable document labels independently within each profile.
    for profile in PROFILE_ORDER:
        profile_sessions = [
            session
            for session in sessions
            if session["configuration"]["profile"] == profile
        ]
        paths = sorted({session["_document_path"] for session in profile_sessions})
        if len(paths) != 2:
            raise ValueError(f"{profile} must contain exactly two source documents")
        labels = {paths[0]: "A", paths[1]: "B"}
        for session in profile_sessions:
            session["_document_label"] = labels[session["_document_path"]]
        per_document = {
            label: sum(
                session["_document_label"] == label for session in profile_sessions
            )
            for label in ("A", "B")
        }
        if per_document != {"A": 4, "B": 4}:
            raise ValueError(
                f"{profile} must contain four sessions for each document; "
                f"found {per_document}"
            )

    return sessions


def profile_sessions(sessions: Sequence[dict], profile: str) -> list[dict]:
    return [
        session
        for session in sessions
        if session["configuration"]["profile"] == profile
    ]


def session_run_mean(session: dict, value: Callable[[dict], float]) -> float:
    return arithmetic_mean([value(run) for run in session["runs"]])


def session_generation_values(
    sessions: Sequence[dict], profile: str, key: str, scale: float
) -> list[float]:
    return [
        session_run_mean(session, lambda run: run["generation"][key] / scale)
        for session in profile_sessions(sessions, profile)
    ]


def configure_matplotlib() -> None:
    plt.rcParams.update(
        {
            "font.family": "serif",
            "font.size": 8.5,
            "axes.labelsize": 8.5,
            "axes.titlesize": 9.5,
            "xtick.labelsize": 8,
            "ytick.labelsize": 8,
            "legend.fontsize": 7.5,
            "axes.spines.top": False,
            "axes.spines.right": False,
            "axes.grid": False,
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
        }
    )


def save_figure(figure: plt.Figure, output_dir: Path, stem: str) -> None:
    figure.savefig(output_dir / f"{stem}.png", dpi=300, bbox_inches="tight")
    plt.close(figure)


def add_session_points(
    axis: plt.Axes,
    x_center: float,
    values: Sequence[float],
    labels: Sequence[str],
    width: float = 0.22,
) -> None:
    offsets = [
        -width / 2 + width * index / (len(values) - 1)
        for index in range(len(values))
    ]
    for offset, value, label in zip(offsets, values, labels):
        axis.scatter(
            x_center + offset,
            value,
            marker=DOCUMENT_MARKERS[label],
            s=20,
            facecolor="white",
            edgecolor="black",
            linewidth=0.7,
            zorder=5,
        )


def generate_prover_figure(sessions: Sequence[dict], output_dir: Path) -> None:
    figure, (latency_axis, memory_axis) = plt.subplots(
        1, 2, figsize=(7.15, 3.15), constrained_layout=True
    )
    x_positions = list(range(len(PROFILE_ORDER)))

    for x, profile in zip(x_positions, PROFILE_ORDER):
        current_sessions = profile_sessions(sessions, profile)
        labels = [session["_document_label"] for session in current_sessions]
        zktls = session_generation_values(sessions, profile, "zkTlsMs", 1000.0)
        noir = session_generation_values(sessions, profile, "noirTotalMs", 1000.0)
        totals = session_generation_values(sessions, profile, "totalMs", 1000.0)
        zktls_mean = arithmetic_mean(zktls)
        noir_mean = arithmetic_mean(noir)
        total_mean, total_ci = mean_ci95(totals)

        latency_axis.bar(x, zktls_mean, width=0.58, color=ZKTLS_COLOR)
        latency_axis.bar(
            x, noir_mean, bottom=zktls_mean, width=0.58, color=NOIR_COLOR
        )
        latency_axis.errorbar(
            x,
            total_mean,
            yerr=total_ci,
            fmt="none",
            ecolor="black",
            elinewidth=1,
            capsize=3,
            zorder=6,
        )
        add_session_points(latency_axis, x, totals, labels)

        for stage_index, (key, color) in enumerate(
            (("zkTlsPeakRssBytes", ZKTLS_COLOR), ("noirPeakRssBytes", NOIR_COLOR))
        ):
            stage_x = x + (-0.17 if stage_index == 0 else 0.17)
            values = session_generation_values(sessions, profile, key, 2**30)
            value_mean, value_ci = mean_ci95(values)
            memory_axis.bar(stage_x, value_mean, width=0.28, color=color)
            memory_axis.errorbar(
                stage_x,
                value_mean,
                yerr=value_ci,
                fmt="none",
                ecolor="black",
                elinewidth=1,
                capsize=3,
                zorder=6,
            )
            add_session_points(memory_axis, stage_x, values, labels, width=0.10)

    profile_labels = [PROFILE_LABELS[profile] for profile in PROFILE_ORDER]
    latency_axis.set_title("(a) Proof-generation latency")
    latency_axis.set_ylabel("Time (s)")
    latency_axis.set_xticks(x_positions, profile_labels)
    latency_axis.set_ylim(bottom=0)
    latency_axis.grid(axis="y", color="#dddddd", linewidth=0.6, zorder=0)

    memory_axis.set_title("(b) Mean peak process memory")
    memory_axis.set_ylabel("Peak RSS (GiB)")
    memory_axis.set_xticks(x_positions, profile_labels)
    memory_axis.set_ylim(bottom=0)
    memory_axis.grid(axis="y", color="#dddddd", linewidth=0.6, zorder=0)

    stage_legend = [
        Patch(facecolor=ZKTLS_COLOR, label="zkTLS"),
        Patch(facecolor=NOIR_COLOR, label="Noir/UltraHonk"),
    ]
    document_legend = [
        Line2D(
            [0],
            [0],
            marker=DOCUMENT_MARKERS[label],
            linestyle="none",
            markerfacecolor="white",
            markeredgecolor="black",
            markersize=5,
            label=f"Document {label}",
        )
        for label in ("A", "B")
    ]
    latency_axis.legend(handles=stage_legend, loc="upper left", frameon=False)
    memory_axis.legend(handles=document_legend, loc="upper left", frameon=False)

    save_figure(figure, output_dir, "benchmark-prover-cost")


def cold_verification_ms(session: dict) -> float:
    return arithmetic_mean(
        [run["verification"][0]["totalMs"] for run in session["runs"]]
    )


def warm_verification_ms(session: dict) -> float:
    per_proof_means = [
        arithmetic_mean(
            [verification["totalMs"] for verification in run["verification"][1:]]
        )
        for run in session["runs"]
    ]
    return arithmetic_mean(per_proof_means)


def generate_verification_figure(
    sessions: Sequence[dict], output_dir: Path
) -> None:
    figure, axis = plt.subplots(figsize=(7.15, 3.05), constrained_layout=True)
    x_positions = list(range(len(PROFILE_ORDER)))
    offsets = {"cold": -0.16, "warm": 0.16}

    for x, profile in zip(x_positions, PROFILE_ORDER):
        current_sessions = profile_sessions(sessions, profile)
        cold = [cold_verification_ms(session) for session in current_sessions]
        warm = [warm_verification_ms(session) for session in current_sessions]

        jitter = [
            -0.055 + 0.11 * index / (len(current_sessions) - 1)
            for index in range(len(current_sessions))
        ]
        for session_index, session in enumerate(current_sessions):
            marker = DOCUMENT_MARKERS[session["_document_label"]]
            cold_x = x + offsets["cold"] + jitter[session_index]
            warm_x = x + offsets["warm"] + jitter[session_index]
            axis.plot(
                [cold_x, warm_x],
                [cold[session_index], warm[session_index]],
                color="#b9b9b9",
                linewidth=0.7,
                zorder=1,
            )
            axis.scatter(
                cold_x,
                cold[session_index],
                marker=marker,
                s=24,
                color=COLD_COLOR,
                edgecolor="black",
                linewidth=0.5,
                zorder=3,
            )
            axis.scatter(
                warm_x,
                warm[session_index],
                marker=marker,
                s=24,
                color=WARM_COLOR,
                edgecolor="black",
                linewidth=0.5,
                zorder=3,
            )

        for label, values, color in (
            ("cold", cold, COLD_COLOR),
            ("warm", warm, WARM_COLOR),
        ):
            value_mean, value_ci = mean_ci95(values)
            axis.errorbar(
                x + offsets[label],
                value_mean,
                yerr=value_ci,
                fmt="D",
                markersize=5,
                markerfacecolor=color,
                markeredgecolor="black",
                markeredgewidth=0.7,
                ecolor="black",
                elinewidth=1.1,
                capsize=3,
                zorder=5,
            )

    axis.set_title("End-to-end protocol verification")
    axis.set_ylabel("Verification time (ms)")
    axis.set_xticks(
        x_positions, [PROFILE_LABELS[profile] for profile in PROFILE_ORDER]
    )
    axis.set_ylim(bottom=0)
    axis.grid(axis="y", color="#dddddd", linewidth=0.6, zorder=0)

    legend = [
        Patch(facecolor=COLD_COLOR, edgecolor="black", label="First (cold)"),
        Patch(facecolor=WARM_COLOR, edgecolor="black", label="Subsequent (warm)"),
        Line2D(
            [0],
            [0],
            marker="D",
            color="black",
            linestyle="none",
            markerfacecolor="white",
            markersize=5,
            label="Mean with 95% t CI",
        ),
        Line2D(
            [0],
            [0],
            marker=DOCUMENT_MARKERS["A"],
            color="black",
            linestyle="none",
            markerfacecolor="white",
            markersize=5,
            label="Doc. A",
        ),
        Line2D(
            [0],
            [0],
            marker=DOCUMENT_MARKERS["B"],
            color="black",
            linestyle="none",
            markerfacecolor="white",
            markersize=5,
            label="Doc. B",
        ),
    ]
    axis.set_ylim(0, 150)
    axis.legend(handles=legend, loc="upper center", frameon=False, ncol=5)

    save_figure(figure, output_dir, "benchmark-verification")


def print_summary(sessions: Sequence[dict], output_dir: Path) -> None:
    print(f"Generated benchmark artifacts in {output_dir}")
    for profile in PROFILE_ORDER:
        total = session_generation_values(sessions, profile, "totalMs", 1000.0)
        noir_memory = session_generation_values(
            sessions, profile, "noirPeakRssBytes", 2**30
        )
        current_sessions = profile_sessions(sessions, profile)
        cold = [cold_verification_ms(session) for session in current_sessions]
        warm = [warm_verification_ms(session) for session in current_sessions]
        print(
            f"  {PROFILE_LABELS[profile]}: generation {arithmetic_mean(total):.2f} s; "
            f"Noir peak RSS {arithmetic_mean(noir_memory):.2f} GiB; "
            f"verification {arithmetic_mean(cold):.2f} ms cold / "
            f"{arithmetic_mean(warm):.2f} ms warm"
        )


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_INPUT,
        help=f"benchmark JSON file (default: {DEFAULT_INPUT})",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help=f"artifact directory (default: {DEFAULT_OUTPUT_DIR})",
    )
    return parser.parse_args()


def main() -> None:
    arguments = parse_arguments()
    input_path = arguments.input.expanduser().resolve()
    output_dir = arguments.output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    sessions = load_sessions(input_path)
    configure_matplotlib()
    generate_prover_figure(sessions, output_dir)
    generate_verification_figure(sessions, output_dir)
    print_summary(sessions, output_dir)


if __name__ == "__main__":
    main()

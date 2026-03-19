import plotly.express as px
import plotly.graph_objects as go
import pandas as pd


def attack_distribution_chart(by_type: dict):
    if not by_type:
        return go.Figure().update_layout(title="No attack data yet")
    fig = px.pie(
        values=list(by_type.values()),
        names=list(by_type.keys()),
        title="Attack Type Distribution",
        color_discrete_sequence=px.colors.qualitative.Set2,
        hole=0.3,
    )
    fig.update_layout(margin=dict(t=40, b=0, l=0, r=0))
    return fig


def attack_timeline_chart(timeline: list):
    if not timeline:
        return go.Figure().update_layout(title="No timeline data yet")
    df = pd.DataFrame(timeline)
    fig = px.line(
        df, x="date", y="count",
        title="Attacks Over Time",
        markers=True,
        color_discrete_sequence=["#ef4444"],
    )
    fig.update_layout(xaxis_title="Date", yaxis_title="Attacks", margin=dict(t=40, b=0))
    return fig


def severity_bar_chart(by_severity: dict):
    if not by_severity:
        return go.Figure().update_layout(title="No severity data yet")
    colors = {"CRITICAL": "#dc2626", "HIGH": "#f97316", "MEDIUM": "#eab308", "LOW": "#22c55e"}
    fig = go.Figure(go.Bar(
        x=list(by_severity.keys()),
        y=list(by_severity.values()),
        marker_color=[colors.get(k, "#6b7280") for k in by_severity.keys()],
    ))
    fig.update_layout(title="Attacks by Severity", xaxis_title="Severity", yaxis_title="Count", margin=dict(t=40, b=0))
    return fig

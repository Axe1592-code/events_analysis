import json
import os

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns


JSON_PATH = "events.json"

if not os.path.exists(JSON_PATH):
    raise FileNotFoundError(
        f"Файл {JSON_PATH} не найден. Нужен events.json рядом со скриптом."
    )

with open(JSON_PATH, "r", encoding="utf-8") as f:
    data = json.load(f)

df = pd.DataFrame(data["events"])

# Привод timestamp к datetime — пригодится для анализа по времени
df["timestamp"] = pd.to_datetime(df["timestamp"])

# Категория события = первое слово signature (MALWARE-CNC, EXPLOIT, NETBIOS, INDICATOR-COMPROMISE)
df["category"] = df["signature"].str.split().str[0]

# Распределения
signature_counts = df["signature"].value_counts()
category_counts = df["category"].value_counts()

# Анализ
print("=" * 60)
print("АНАЛИЗ ДАННЫХ")
print("=" * 60)
print(f"Всего событий:        {len(df)}")
print(f"Уникальных signature: {df['signature'].nunique()}")
print(f"Уникальных категорий: {df['category'].nunique()}")
print(f"Период:               {df['timestamp'].min()} — {df['timestamp'].max()}")
print("\nРаспределение по signature:")
print(signature_counts.to_string())
print("\nРаспределение по категориям:")
print(category_counts.to_string())
print("\nСобытия по дням:")
print(df.groupby(df["timestamp"].dt.date).size().to_string())

# Визуализация
sns.set_theme(style="whitegrid", palette="viridis")
plt.rcParams["font.family"] = "DejaVu Sans"

fig, axes = plt.subplots(1, 2, figsize=(18, 7))

# --- График 1: распределение по signature (основное требование задания) ---
sns.countplot(
    data=df,
    y="signature",
    order=signature_counts.index,
    ax=axes[0],
    hue="signature",
    legend=False,
)
axes[0].set_title(
    "Распределение типов событий безопасности (signature)",
    fontsize=13, fontweight="bold",
)
axes[0].set_xlabel("Количество событий")
axes[0].set_ylabel("Тип события (signature)")
for container in axes[0].containers:
    axes[0].bar_label(container, padding=3, fontsize=9)

# --- График 2: распределение по категориям (дополнительно) ---
sns.countplot(
    data=df,
    x="category",
    order=category_counts.index,
    ax=axes[1],
    hue="category",
    legend=False,
)
axes[1].set_title(
    "Распределение событий по категориям",
    fontsize=13, fontweight="bold",
)
axes[1].set_xlabel("Категория")
axes[1].set_ylabel("Количество событий")
axes[1].tick_params(axis="x", rotation=20)
for container in axes[1].containers:
    axes[1].bar_label(container, padding=3, fontsize=9)

plt.suptitle(
    "Анализ событий информационной безопасности",
    fontsize=15, fontweight="bold",
)
plt.tight_layout(rect=[0, 0, 1, 0.96])
plt.savefig("events_distribution.png", dpi=150, bbox_inches="tight")
plt.show()

print("\n[+] График сохранён в файл: events_distribution.png")

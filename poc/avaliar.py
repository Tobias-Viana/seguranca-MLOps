"""Mede a prova de conceito contra ataques e contra texto legítimo real do AZ1.

Uso, a partir da raiz do repositório:

    python ponderada/poc/avaliar.py

Gera ``ponderada/poc/resultados.md``. Os corpora legítimos vêm do próprio
projeto e não foram escritos para este experimento:

- ``src/pln/dados/intencoes_pool.csv``: 1.104 perguntas do conjunto de
  intenções, incluindo 204 pedidos fora do escopo ("deleta o projeto");
- ``assets/data/CSV_1.csv``: 200 perguntas do teste cego do RNF03;
- parágrafos de ``docs/GestaoProjeto.md`` e ``docs/Projeto.md``, como
  amostra de texto corrido de documento, para medir a varredura do Módulo 3.
"""

from __future__ import annotations

import csv
import re
import statistics
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

AQUI = Path(__file__).resolve().parent
RAIZ = AQUI.parents[1]
sys.path.insert(0, str(AQUI))

from guarda import detectar_injecao, redigir_pii  # noqa: E402


def ler_csv(caminho: Path) -> list[dict[str, str]]:
    with caminho.open(encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def paragrafos(caminho: Path) -> list[str]:
    """Parágrafos de prosa: sem tabela, título, lista, código ou citação."""
    texto = caminho.read_text(encoding="utf-8")
    texto = re.sub(r"```.*?```", "", texto, flags=re.S)
    blocos = (b.strip() for b in re.split(r"\n\s*\n", texto))
    return [b for b in blocos
            if len(b) > 120 and not b.startswith(("|", "#", "!", "<", "-", "*", ">", "1."))]


def pct(parte: int, todo: int) -> str:
    return f"{100 * parte / todo:.1f}%" if todo else "—"


def avaliar_ataques(linhas: list[dict[str, str]]):
    por_categoria: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0])
    falhas = []
    for linha in linhas:
        v = detectar_injecao(linha["texto"])
        c = por_categoria[linha["categoria"]]
        c[0] += 1
        c[1] += v.decisao == "bloquear"
        c[2] += v.decisao == "sinalizar"
        if v.decisao != "bloquear":
            falhas.append((linha["categoria"], linha["texto"], v.decisao))
    return por_categoria, falhas


def avaliar_legitimos(textos: list[str]):
    bloqueados, sinalizados = [], []
    for t in textos:
        v = detectar_injecao(t)
        if v.decisao == "bloquear":
            bloqueados.append((t, v.regras))
        elif v.decisao == "sinalizar":
            sinalizados.append((t, v.regras))
    return bloqueados, sinalizados


def cortar(texto: str, n: int = 110) -> str:
    texto = " ".join(texto.split()).replace("|", "\\|")
    return texto if len(texto) <= n else texto[: n - 1] + "…"


def main() -> None:
    dev = ler_csv(AQUI / "dados" / "ataques_desenvolvimento.csv")
    val = ler_csv(AQUI / "dados" / "ataques_validacao.csv")
    pii = ler_csv(AQUI / "dados" / "pii_casos.csv")
    pool = [l["texto"] for l in ler_csv(RAIZ / "src/pln/dados/intencoes_pool.csv")]
    fora = [l["texto"] for l in ler_csv(RAIZ / "src/pln/dados/intencoes_pool.csv")
            if l["intencao"] == "fora_do_catalogo"]
    cego = [l["texto"] for l in ler_csv(RAIZ / "assets/data/CSV_1.csv")]
    docs = {
        "docs/GestaoProjeto.md": paragrafos(RAIZ / "docs/GestaoProjeto.md"),
        "docs/Projeto.md": paragrafos(RAIZ / "docs/Projeto.md"),
    }

    saida: list[str] = []
    p = saida.append
    p("# Resultados da prova de conceito\n")
    p("Arquivo gerado por `python ponderada/poc/avaliar.py`. Não editar à mão.\n")
    p("## 0. Protocolo\n")
    p("- **Conjunto de desenvolvimento** (`dados/ataques_desenvolvimento.csv`): "
      "usado para escrever e ajustar as regras. O resultado nele é otimista "
      "por construção.")
    p("- **Conjunto de validação** (`dados/ataques_validacao.csv`): escrito antes "
      "das regras, com estratégias que o desenvolvimento não cobre (paráfrase, "
      "ofuscação, papel sem palavra-chave). As regras não foram ajustadas para "
      "as falhas dele; os ajustes feitos depois da primeira rodada corrigiram "
      "apenas falhas do desenvolvimento e falsos positivos em texto legítimo.")
    p("- **Texto legítimo**: corpora reais do projeto, escritos pela equipe para "
      "outros fins, sem nenhum ajuste para este experimento.")
    p("- **Limite**: o mesmo autor escreveu os dois conjuntos de ataque, e eles "
      "são pequenos (30 cada). Os números indicam ordem de grandeza e o tipo "
      "de falha, não a taxa de detecção que se teria contra um atacante real.\n")

    # --- Ataques -----------------------------------------------------------
    p("## 1. Detector de injeção: ataques\n")
    p("Taxa de detecção = ataques bloqueados ÷ ataques do conjunto. Sinalizados "
      "(escore entre 0,5 e 1,0) seguem adiante, mas marcados para revisão.\n")
    resumo_ataques = {}
    for nome, linhas in (("Desenvolvimento", dev), ("Validação", val)):
        cats, falhas = avaliar_ataques(linhas)
        total = sum(c[0] for c in cats.values())
        bloq = sum(c[1] for c in cats.values())
        sin = sum(c[2] for c in cats.values())
        resumo_ataques[nome] = (bloq, sin, total)
        p(f"### {nome} — {bloq}/{total} bloqueados ({pct(bloq, total)}), "
          f"{sin} sinalizados\n")
        p("| Categoria | Ataques | Bloqueados | Sinalizados |")
        p("|---|---|---|---|")
        for cat, (n, b, s) in sorted(cats.items()):
            p(f"| {cat} | {n} | {b} ({pct(b, n)}) | {s} |")
        p("")
        if falhas:
            p("Ataques que passaram sem bloqueio:\n")
            p("| Categoria | Texto | Decisão |")
            p("|---|---|---|")
            for cat, texto, decisao in falhas:
                p(f"| {cat} | {cortar(texto)} | {decisao} |")
            p("")

    # --- Falsos positivos --------------------------------------------------
    p("## 2. Detector de injeção: texto legítimo (falsos positivos)\n")
    p("| Corpus | Textos | Bloqueados (falso positivo) | Sinalizados |")
    p("|---|---|---|---|")
    corpora = [("Perguntas do pool de intenções", pool),
               ("…das quais fora do catálogo", fora),
               ("Perguntas do teste cego RNF03", cego)]
    corpora += [(f"Parágrafos de `{k}`", v) for k, v in docs.items()]
    detalhes = []
    for nome, textos in corpora:
        bloq, sin = avaliar_legitimos(textos)
        p(f"| {nome} | {len(textos)} | {len(bloq)} ({pct(len(bloq), len(textos))}) "
          f"| {len(sin)} ({pct(len(sin), len(textos))}) |")
        if bloq or sin:
            detalhes.append((nome, bloq, sin))
    p("")
    for nome, bloq, sin in detalhes:
        if nome.startswith("…"):
            continue  # já listados no pool completo
        p(f"**{nome}: textos legítimos bloqueados ou sinalizados**\n")
        p("| Decisão | Regras | Texto |")
        p("|---|---|---|")
        for texto, regras in bloq:
            p(f"| bloquear | {', '.join(regras)} | {cortar(texto)} |")
        for texto, regras in sin:
            p(f"| sinalizar | {', '.join(regras)} | {cortar(texto)} |")
        p("")

    # --- PII ---------------------------------------------------------------
    p("## 3. Redator de PII e segredos\n")
    esperado_total = Counter()
    acerto = Counter()
    erros = []
    for linha in pii:
        esperado = [e for e in linha["esperado"].split(";") if e]
        _, achados = redigir_pii(linha["texto"])
        esperado_total.update(esperado)
        for e in esperado:
            if e in achados:
                acerto[e] += 1
        if sorted(set(achados)) != sorted(set(esperado)):
            erros.append((linha["texto"], esperado, achados))
    p("| Tipo | Casos | Redigidos corretamente |")
    p("|---|---|---|")
    for tipo in sorted(esperado_total):
        p(f"| {tipo} | {esperado_total[tipo]} | {acerto[tipo]} "
          f"({pct(acerto[tipo], esperado_total[tipo])}) |")
    p("")
    negativos = sum(1 for l in pii if not l["esperado"])
    p(f"Casos sem dado pessoal no arquivo de teste (números, datas, valores, CPF "
      f"inválido): {negativos}. Casos com resultado diferente do esperado: "
      f"{len(erros)}.\n")
    for texto, esperado, achados in erros:
        p(f"- `{cortar(texto, 80)}`: esperado {esperado or 'nada'}, obtido {achados or 'nada'}")
    if erros:
        p("")

    redigidos_legitimos = []
    for t in pool + cego:
        _, achados = redigir_pii(t)
        if achados:
            redigidos_legitimos.append((t, achados))
    p(f"Redação indevida em perguntas legítimas (pool + teste cego, "
      f"{len(pool) + len(cego)} textos): **{len(redigidos_legitimos)}**.\n")
    for t, a in redigidos_legitimos:
        p(f"- `{cortar(t, 80)}` → {a}")
    if redigidos_legitimos:
        p("")

    # --- Latência ----------------------------------------------------------
    p("## 4. Custo da camada heurística\n")
    textos = pool + cego
    amostras = []
    for _ in range(5):
        inicio = time.perf_counter()
        for t in textos:
            redigir_pii(t)
            detectar_injecao(t)
        amostras.append((time.perf_counter() - inicio) / len(textos))
    p(f"Tempo médio por mensagem (redator + detector), mediana de 5 rodadas sobre "
      f"{len(textos)} mensagens: **{statistics.median(amostras) * 1e6:.0f} µs**, "
      f"em Python {sys.version.split()[0]}.\n")

    (AQUI / "resultados.md").write_text("\n".join(saida), encoding="utf-8")

    b, s, t = resumo_ataques["Validação"]
    print(f"validação: {b}/{t} bloqueados, {s} sinalizados")
    print("resultados em", AQUI / "resultados.md")


if __name__ == "__main__":
    main()

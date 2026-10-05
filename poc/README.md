# Prova de conceito: camadas determinísticas de segurança

Implementação mínima de quatro peças da proposta descrita em [../README.md](../README.md), escrita para medir na prática o que o texto afirma. O código não altera o AZ1: roda isolado e lê os dados do repositório só para medir.

| Arquivo | O que é | Módulo da proposta |
|---|---|---|
| [guarda.py](guarda.py) | `redigir_pii`, `detectar_injecao`, `montar_prompt_delimitado`, `verificar_citacoes` | 2, 3, 4 e 5 |
| [avaliar.py](avaliar.py) | Mede o detector e o redator contra ataques e contra texto legítimo real do projeto | 8 (protótipo) |
| [test_guarda.py](test_guarda.py) | 16 testes unitários | 8 (protótipo) |
| [dados/](dados/) | 60 ataques em português e inglês (30 de desenvolvimento e 30 de validação) e 23 casos de PII | — |
| [resultados.md](resultados.md) | Relatório gerado pelo `avaliar.py` | — |

## Como rodar

Só usa a biblioteca padrão do Python (3.10 ou superior). Rode a partir da raiz do repositório:

```bash
python -m unittest discover -s ponderada/poc -v   # testes
python ponderada/poc/avaliar.py                   # regenera resultados.md
```

## O que ficou de fora, de propósito

- **A segunda camada do detector**, o classificador por modelo. A prova de conceito mede só a camada heurística, que é a mais barata. As falhas dela, listadas no relatório, são exatamente o espaço que a segunda camada precisa cobrir.
- **A integração com a API.** Ligar `redigir_pii` e `detectar_injecao` em `src/routes/chat.py` e `montar_prompt_delimitado` em `src/services/gemini_service.py` é o trabalho de implementação estimado no Quadro 3 da proposta.

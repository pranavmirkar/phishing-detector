"""
Levenshtein Distance — hand-coded DP, no external libraries.

Operations and their costs:
  insert     : +1
  delete     : +1
  substitute : +1

dp[i][j] = minimum edits to convert s1[:i] into s2[:j]
"""


def levenshtein_distance(s1: str, s2: str) -> int:
    m, n = len(s1), len(s2)
    dp = [[0] * (n + 1) for _ in range(m + 1)]

    for i in range(m + 1):
        dp[i][0] = i          # delete all chars of s1[:i]
    for j in range(n + 1):
        dp[0][j] = j          # insert all chars of s2[:j]

    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if s1[i - 1] == s2[j - 1]:
                dp[i][j] = dp[i - 1][j - 1]          # no edit needed
            else:
                dp[i][j] = 1 + min(
                    dp[i - 1][j],       # delete from s1
                    dp[i][j - 1],       # insert into s1
                    dp[i - 1][j - 1],   # substitute
                )

    return dp[m][n]


def get_dp_matrix(s1: str, s2: str) -> dict:
    """Full DP table + traceback path for the visual matrix renderer."""
    m, n = len(s1), len(s2)
    dp = [[0] * (n + 1) for _ in range(m + 1)]

    for i in range(m + 1):
        dp[i][0] = i
    for j in range(n + 1):
        dp[0][j] = j

    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if s1[i - 1] == s2[j - 1]:
                dp[i][j] = dp[i - 1][j - 1]
            else:
                dp[i][j] = 1 + min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1])

    # Traceback from bottom-right to top-left
    path = set()
    i, j = m, n
    while i > 0 or j > 0:
        path.add((i, j))
        if i > 0 and j > 0 and s1[i - 1] == s2[j - 1]:
            i -= 1; j -= 1
        elif i > 0 and j > 0 and dp[i][j] == dp[i - 1][j - 1] + 1:
            i -= 1; j -= 1
        elif j > 0 and dp[i][j] == dp[i][j - 1] + 1:
            j -= 1
        else:
            i -= 1
    path.add((0, 0))

    return {
        "matrix": dp,
        "path": [list(p) for p in path],
        "s1": s1,
        "s2": s2,
        "distance": dp[m][n],
    }


def get_edit_operations(s1: str, s2: str) -> list:
    """Returns ordered list of edit operations for the diff visualizer."""
    m, n = len(s1), len(s2)
    dp = [[0] * (n + 1) for _ in range(m + 1)]

    for i in range(m + 1):
        dp[i][0] = i
    for j in range(n + 1):
        dp[0][j] = j

    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if s1[i - 1] == s2[j - 1]:
                dp[i][j] = dp[i - 1][j - 1]
            else:
                dp[i][j] = 1 + min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1])

    ops = []
    i, j = m, n
    while i > 0 or j > 0:
        if i > 0 and j > 0 and s1[i - 1] == s2[j - 1]:
            ops.append({"type": "match", "char": s1[i - 1], "pos": i - 1})
            i -= 1; j -= 1
        elif i > 0 and j > 0 and dp[i][j] == dp[i - 1][j - 1] + 1:
            ops.append({
                "type": "substitute",
                "from_char": s1[i - 1],
                "to_char": s2[j - 1],
                "pos": i - 1,
                "description": f"'{s1[i-1]}' substituted with '{s2[j-1]}' at position {i}",
            })
            i -= 1; j -= 1
        elif j > 0 and dp[i][j] == dp[i][j - 1] + 1:
            ops.append({
                "type": "insert",
                "char": s2[j - 1],
                "pos": j - 1,
                "description": f"insert '{s2[j-1]}' at position {j}",
            })
            j -= 1
        else:
            ops.append({
                "type": "delete",
                "char": s1[i - 1],
                "pos": i - 1,
                "description": f"delete '{s1[i-1]}' at position {i}",
            })
            i -= 1

    ops.reverse()
    return ops


def similarity_percent(s1: str, s2: str) -> float:
    dist = levenshtein_distance(s1, s2)
    max_len = max(len(s1), len(s2), 1)
    return round((1 - dist / max_len) * 100, 1)

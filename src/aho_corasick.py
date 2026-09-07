def make_trie(patterns):
    goto = [{}]
    output = [[]]
    
    for pattern in patterns:
        node = 0

        for char in pattern:
            if char not in goto[node]:
                goto[node][char] = len(goto)
                goto.append({})
                output.append([])
            node = goto[node][char]
        output[node].append(pattern)
    
    return goto, output


def make_fail(goto, output):
    fail = [0] * len(goto)
    queue = []
    
    for char, node in goto[0].items():
        fail[node] = 0
        queue.append(node)
    
    while queue:
        r = queue.pop(0)
        for char, s in goto[r].items():
            queue.append(s)
            state = fail[r]

            while state != 0 and char not in goto[state]:
                state = fail[state]

            fail[s] = goto[state].get(char, 0)

            if fail[s] == s:
                fail[s] = 0
            
            output[s] += output[fail[s]]
    
    return fail, output


def search(text, goto, fail, output):
    node = 0
    results = []
    
    for i, char in enumerate(text):
        while node != 0 and char not in goto[node]:
            node = fail[node]
        
        node = goto[node].get(char, 0)

        for pattern in output[node]:
            results.append((i - len(pattern) + 1, pattern))
    
    return results


def aho_corasick(text, patterns):
    goto, output = make_trie(patterns)
    fail, output = make_fail(goto, output)
    results = search(text, goto, fail, output)
    return results if results else -1

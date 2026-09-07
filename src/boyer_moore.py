def boyer_moore(text: str, pattern: str):
    text = text.upper()
    bad_array = bad_table(pattern)
    good_array = good_table(pattern)

    index = len(pattern) - 1

    while index < len(text):
        temp_index = index
        mismatch = False

        while temp_index > index - len(pattern):
            if text[temp_index] == pattern[len(pattern)-(index - temp_index)-1]:
                temp_index -= 1
            else:
                pat_pos = len(pattern) - (index - temp_index)-1
                matched_len = index - temp_index
                
                last_char = bad_array[pat_pos][ord(text[temp_index]) - ord('A')]
                bad_shift = pat_pos - last_char if last_char != -1 else pat_pos + 1
                good_shift = good_array[matched_len] if matched_len > 0 else 1
                
                index += max(1, max(bad_shift, good_shift))
                mismatch = True

                break

        if not mismatch and temp_index == index - len(pattern):
            return temp_index + 1

    return -1


def bad_table(pattern: str):
    temp = [-1] * 26
    bad_array = [[-1] * 26 for _ in range(len(pattern))]

    for i in range(len(pattern)):
        bad_array[i] = temp.copy()
        temp[ord(pattern[i])-ord('A')] = i
    
    return bad_array


def good_table(pattern: str):
    good_array = [-1] * len(pattern)

    for i in range(len(pattern)-1, -1, -1):
        suffix = pattern[i:]
        match = False

        for j in range(i-1, -1, -1):
            if pattern[j:j+len(suffix)] == suffix:
                good_array[len(pattern)-i-1] = i-j
                match = True
                break
        
        if not match:
            for k in range(len(suffix)-1, 0, -1):
                if suffix[-k:] == pattern[:k]:
                    good_array[len(pattern)-i-1] = len(pattern) - k
                    break
            if good_array[len(pattern)-i-1] == -1:
                good_array[len(pattern)-i-1] = len(pattern)

    return good_array

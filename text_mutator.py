import random
from pathlib import Path
from cryptography.fernet import Fernet

class TextMutationTests:
    def __init__(self, folder: str):
        self.folder = Path(folder)
        self.target_files = list(self.folder.glob("*.txt"))

    def corrupt_to_non_ascii(self):
        selected_files = random.sample(self.target_files, min(2, len(self.target_files)))
        for file in selected_files:
            corrupt_text = ''.join(chr(random.randint(128, 255)) for _ in range(300))
            file.write_text(corrupt_text, encoding='utf-8')
            print(f"[MUTATE] Non-ASCII corruption applied to {file.name}")

    def encrypt_line_simulation(self):
        gibberish = "q6oJKN8GIaRCEkP7iY46boHjWSfTrx2qHeWLcn71o6TkS9Ey"
        selected_files = random.sample(self.target_files, min(2, len(self.target_files)))
        for file in selected_files:
            lines = file.read_text(encoding='utf-8').splitlines()
            if lines:
                idx = random.randint(0, len(lines)-1)
                lines[idx] = gibberish
                file.write_text('\n'.join(lines), encoding='utf-8')
                print(f"[MUTATE] Encrypted-like line inserted in {file.name} (line {idx})")

    def reverse_and_scramble(self):
        selected_files = random.sample(self.target_files, min(2, len(self.target_files)))
        for file in selected_files:
            lines = file.read_text(encoding='utf-8').splitlines()
            scrambled = []
            for i, line in enumerate(lines):
                words = line.split()
                reversed_line = ' '.join(word[::-1] for word in words)
                scrambled.append(reversed_line)
            if scrambled:
                random_line = random.choice(scrambled)
                words = random_line.split()
                random.shuffle(words)
                scrambled[random.randint(0, len(scrambled)-1)] = ' '.join(words)
                file.write_text('\n'.join(scrambled), encoding='utf-8')
                print(f"[MUTATE] Reversed & scrambled applied to {file.name}")

    def scramble_one_line(self):
        """Scramble one line in a random file by shuffling its characters."""
        selected_files = random.sample(self.target_files, min(1, len(self.target_files)))
        for file in selected_files:
            lines = file.read_text(encoding='utf-8').splitlines()
            if not lines:
                continue
            idx = random.randint(0, len(lines)-1)
            original = lines[idx]
            chars = list(original)
            random.shuffle(chars)
            lines[idx] = ''.join(chars)
            file.write_text('\n'.join(lines), encoding='utf-8')
            print(f"[MUTATE] Scrambled one line in {file.name} (line {idx})")

    def encrypt_with_fernet(self):
        key = Fernet.generate_key()
        cipher = Fernet(key)
        selected_files = random.sample(self.target_files, min(1, len(self.target_files)))
        for file in selected_files:
            data = file.read_bytes()
            encrypted = cipher.encrypt(data)
            file.write_bytes(encrypted)
            print(f"[MUTATE] Fernet encryption applied to {file.name}")


    def run_all(self):
        self.corrupt_to_non_ascii()
        self.encrypt_line_simulation()
        self.reverse_and_scramble()
        self.scramble_one_line()
        self.encrypt_with_fernet()
    


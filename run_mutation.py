from text_mutator import TextMutationTests

mutator = TextMutationTests("./test_text_files")
# mutator.corrupt_to_non_ascii()
# mutator.encrypt_line_simulation()
mutator.reverse_and_scramble()
# mutator.scramble_one_line()
# mutator.encrypt_with_fernet()
# mutator.encrypt_with_aes()
# mutator.encrypt_with_des()
# mutator.run_all()
# self.corrupt_to_non_ascii()
#         self.encrypt_line_simulation()
#         self.reverse_and_scramble()
#         self.scramble_one_line()
#         self.encrypt_with_fernet()

# encrypt_with_fernet() – מצפינה קובץ אחד באמצעות Fernet (אלגוריתם סימטרי מודרני עם אימות).
# encrypt_with_aes() – מצפינה קובץ אחד עם AES במצב EAX (כולל אימות באמצעות tag).
#corrupt_to_non_ascii() – מחליפה את תוכן שני קבצים אקראיים בטקסט אקראי שאינו ASCII.
# encrypt_line_simulation() – מחליפה שורה אקראית בשני קבצים בטקסט ג'יבריש שנראה כמו פלט מוצפן.
# reverse_and_scramble() – הופכת כל מילה בשורות לשיקוף ומערבבת מילים בשורה אקראית.
# scramble_one_line() – מערבבת את התווים בשורה אחת אקראית מתוך קובץ אקראי.
# encrypt_with_des() – מצפינה קובץ אחד עם DES במצב ECB וריפוד רווחים (לצורכי הדמיה בלבד).

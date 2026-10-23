"""Give basic local feedback about a password entered interactively."""


def assess_password(password: str) -> tuple[int, list[str]]:
    """Return a simple score and improvement suggestions."""
    score = 0
    suggestions = []

    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        suggestions.append("Use a longer password or passphrase (12+ characters is a useful target).")

    checks = [
        (any(char.islower() for char in password), "Add lowercase letters if appropriate."),
        (any(char.isupper() for char in password), "Add uppercase letters if appropriate."),
        (any(char.isdigit() for char in password), "Consider including digits."),
        (any(not char.isalnum() for char in password), "Consider including symbols."),
    ]
    for passed, suggestion in checks:
        if passed:
            score += 1
        else:
            suggestions.append(suggestion)

    return score, suggestions


def main() -> None:
    password = input("Enter a sample password to assess (input is not saved): ")
    score, suggestions = assess_password(password)
    print(f"Rule-based score: {score}/6")
    if not suggestions:
        print("The sample meets all checks in this simple tool.")
    else:
        print("Suggestions:")
        for suggestion in suggestions:
            print(f"- {suggestion}")
    print("Reminder: this score is educational and does not guarantee password security.")


if __name__ == "__main__":
    main()

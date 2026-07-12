from ui.app import App


def main() -> None:
    try:
        app = App()
        app.mainloop()
    except Exception as e:
        print(f"Fehler beim Starten der Anwendung: {e}")
        raise


if __name__ == "__main__":
    main()

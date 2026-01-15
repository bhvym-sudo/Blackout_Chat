package ui

import (
	"fmt"
	"log"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/blackout/secure-messenger/internal/chat"
	"github.com/blackout/secure-messenger/internal/crypto"
	"github.com/blackout/secure-messenger/internal/database"
)

type App struct {
	fyneApp     fyne.App
	mainWindow  fyne.Window
	chatManager *chat.Manager
	identity    *database.Contact // For displaying own identity

	contactList  *widget.List
	chatView     *container.Scroll
	messageEntry *widget.Entry
	sendButton   *widget.Button
	statusLabel  *widget.Label
	headerLabel  *widget.Label

	contacts        []*database.Contact
	selectedContact *database.Contact
	messages        []*database.Message
}

func NewApp(chatManager *chat.Manager, onionAddr, publicKey, fingerprint string) *App {
	a := &App{
		fyneApp:     app.New(),
		chatManager: chatManager,
		contacts:    make([]*database.Contact, 0),
		messages:    make([]*database.Message, 0),
		identity: &database.Contact{
			Name:         "Me",
			OnionAddress: onionAddr,
			PublicKey:    publicKey,
			Fingerprint:  fingerprint,
		},
	}

	chatManager.AddListener(a)

	return a
}

func (a *App) Run() {
	a.mainWindow = a.fyneApp.NewWindow("Blackout - Secure P2P Messenger")
	a.mainWindow.Resize(fyne.NewSize(1000, 700))
	a.mainWindow.SetMaster()

	content := a.buildUI()
	a.mainWindow.SetContent(content)

	a.refreshContacts()

	a.mainWindow.ShowAndRun()
}

func (a *App) buildUI() fyne.CanvasObject {

	leftPanel := a.buildContactListPanel()

	rightPanel := a.buildChatPanel()

	split := container.NewHSplit(leftPanel, rightPanel)
	split.Offset = 0.3

	return split
}

func (a *App) buildContactListPanel() fyne.CanvasObject {

	title := widget.NewLabelWithStyle("Contacts", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})

	a.contactList = widget.NewList(
		func() int {
			return len(a.contacts)
		},
		func() fyne.CanvasObject {
			return container.NewVBox(
				widget.NewLabel("Contact Name"),
				widget.NewLabel("Status"),
			)
		},
		func(i widget.ListItemID, obj fyne.CanvasObject) {
			contact := a.contacts[i]
			cont := obj.(*fyne.Container)

			nameLabel := cont.Objects[0].(*widget.Label)
			statusLabel := cont.Objects[1].(*widget.Label)

			nameLabel.SetText(contact.Name)

			if a.chatManager.IsContactOnline(contact.ID) {
				statusLabel.SetText("🟢 Online")
			} else if contact.LastSeen != nil {
				statusLabel.SetText(fmt.Sprintf("Last seen: %s", contact.LastSeen.Format("15:04")))
			} else {
				statusLabel.SetText("⚫ Offline")
			}
		},
	)

	a.contactList.OnSelected = func(id widget.ListItemID) {
		a.selectContact(a.contacts[id])
	}

	addButton := widget.NewButton("Add Contact", func() {
		a.showAddContactDialog()
	})

	identityButton := widget.NewButton("My Identity", func() {
		a.showIdentityDialog()
	})

	buttons := container.NewVBox(
		addButton,
		identityButton,
	)

	return container.NewBorder(title, buttons, nil, nil, a.contactList)
}

func (a *App) buildChatPanel() fyne.CanvasObject {

	a.headerLabel = widget.NewLabelWithStyle("Select a contact to start chatting", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	a.statusLabel = widget.NewLabel("")

	header := container.NewVBox(a.headerLabel, a.statusLabel)

	chatContainer := container.NewVBox()
	a.chatView = container.NewScroll(chatContainer)
	a.chatView.SetMinSize(fyne.NewSize(600, 400))

	a.messageEntry = widget.NewMultiLineEntry()
	a.messageEntry.SetPlaceHolder("Type a message...")
	a.messageEntry.Wrapping = fyne.TextWrapWord

	a.sendButton = widget.NewButtonWithIcon("Send", theme.MailSendIcon(), func() {
		a.sendMessage()
	})
	a.sendButton.Disable()

	inputArea := container.NewBorder(nil, nil, nil, a.sendButton, a.messageEntry)

	return container.NewBorder(header, inputArea, nil, nil, a.chatView)
}

func (a *App) refreshContacts() {
	contacts, err := a.chatManager.GetAllContacts()
	if err != nil {
		log.Printf("Failed to load contacts: %v", err)
		return
	}

	a.contacts = contacts
	if a.contactList != nil {
		a.contactList.Refresh()
	}
}

func (a *App) selectContact(contact *database.Contact) {
	a.selectedContact = contact

	a.headerLabel.SetText(contact.Name)

	if a.chatManager.IsContactOnline(contact.ID) {
		a.statusLabel.SetText("🟢 Online")
	} else if contact.LastSeen != nil {
		a.statusLabel.SetText(fmt.Sprintf("Last seen: %s", contact.LastSeen.Format("Jan 02, 15:04")))
	} else {
		a.statusLabel.SetText("⚫ Offline")
	}

	a.loadMessages()

	a.chatManager.MarkMessagesRead(contact.ID)

	a.messageEntry.Enable()
	a.sendButton.Enable()
}

func (a *App) loadMessages() {
	if a.selectedContact == nil {
		return
	}

	messages, err := a.chatManager.GetMessages(a.selectedContact.ID, 100, 0)
	if err != nil {
		log.Printf("Failed to load messages: %v", err)
		return
	}

	a.messages = messages

	chatContainer := container.NewVBox()
	for _, msg := range messages {
		chatContainer.Add(a.createMessageWidget(msg))
	}

	a.chatView.Content = chatContainer
	a.chatView.Refresh()
	a.chatView.ScrollToBottom()
}

func (a *App) createMessageWidget(msg *database.Message) fyne.CanvasObject {
	timeStr := msg.Timestamp.Format("15:04")

	var messageWidget fyne.CanvasObject

	if msg.IsOutgoing {

		text := widget.NewLabel(msg.Content)
		text.Wrapping = fyne.TextWrapWord

		timeLabel := widget.NewLabel(timeStr)
		timeLabel.TextStyle = fyne.TextStyle{Italic: true}

		bubble := container.NewVBox(text, timeLabel)
		messageWidget = container.NewHBox(layout.NewSpacer(), bubble)
	} else {

		text := widget.NewLabel(msg.Content)
		text.Wrapping = fyne.TextWrapWord

		timeLabel := widget.NewLabel(timeStr)
		timeLabel.TextStyle = fyne.TextStyle{Italic: true}

		bubble := container.NewVBox(text, timeLabel)
		messageWidget = container.NewHBox(bubble, layout.NewSpacer())
	}

	return messageWidget
}

func (a *App) sendMessage() {
	if a.selectedContact == nil {
		return
	}

	content := strings.TrimSpace(a.messageEntry.Text)
	if content == "" {
		return
	}

	err := a.chatManager.SendMessage(a.selectedContact.ID, content)
	if err != nil {
		dialog.ShowError(fmt.Errorf("Failed to send message: %v", err), a.mainWindow)
		return
	}

	a.messageEntry.SetText("")

	a.loadMessages()
}

func (a *App) showAddContactDialog() {
	nameEntry := widget.NewEntry()
	nameEntry.SetPlaceHolder("Contact Name")

	addressEntry := widget.NewEntry()
	addressEntry.SetPlaceHolder("Onion Address (e.g., abc123...xyz.onion)")

	publicKeyEntry := widget.NewMultiLineEntry()
	publicKeyEntry.SetPlaceHolder("Public Key (base64)")
	publicKeyEntry.SetMinRowsVisible(3)

	formContent := container.NewVBox(
		widget.NewLabelWithStyle("Name:", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		nameEntry,
		widget.NewLabelWithStyle("Onion Address:", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		addressEntry,
		widget.NewLabelWithStyle("Public Key:", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		publicKeyEntry,
	)

	var customDialog dialog.Dialog
	addButton := widget.NewButton("Add", func() {
		name := strings.TrimSpace(nameEntry.Text)
		address := strings.TrimSpace(addressEntry.Text)
		publicKey := strings.TrimSpace(publicKeyEntry.Text)

		if name == "" || address == "" || publicKey == "" {
			dialog.ShowError(fmt.Errorf("All fields are required"), a.mainWindow)
			return
		}

		err := a.chatManager.AddContact(name, address, publicKey)
		if err != nil {
			dialog.ShowError(fmt.Errorf("Failed to add contact: %v", err), a.mainWindow)
			return
		}

		a.refreshContacts()

		dialog.ShowInformation("Success", fmt.Sprintf("Contact %s added successfully!", name), a.mainWindow)
		customDialog.Hide()
	})

	cancelButton := widget.NewButton("Cancel", func() {
		customDialog.Hide()
	})

	buttonBar := container.NewHBox(
		layout.NewSpacer(),
		cancelButton,
		addButton,
	)

	dialogContent := container.NewBorder(
		nil,
		buttonBar,
		nil,
		nil,
		formContent,
	)

	customDialog = dialog.NewCustom("Add Contact", "", dialogContent, a.mainWindow)
	customDialog.Resize(fyne.NewSize(600, 400))
	customDialog.Show()
}

func (a *App) showIdentityDialog() {
	formattedFingerprint := crypto.FormatFingerprint(a.identity.Fingerprint)

	content := container.NewVBox(
		widget.NewLabel("Share this information with contacts:"),
		widget.NewSeparator(),

		widget.NewLabelWithStyle("Onion Address:", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewLabel(a.identity.OnionAddress),
		widget.NewButton("Copy", func() {
			a.mainWindow.Clipboard().SetContent(a.identity.OnionAddress)
			dialog.ShowInformation("Copied", "Onion address copied to clipboard", a.mainWindow)
		}),

		widget.NewSeparator(),

		widget.NewLabelWithStyle("Public Key:", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewLabel(a.identity.PublicKey),
		widget.NewButton("Copy", func() {
			a.mainWindow.Clipboard().SetContent(a.identity.PublicKey)
			dialog.ShowInformation("Copied", "Public key copied to clipboard", a.mainWindow)
		}),

		widget.NewSeparator(),

		widget.NewLabelWithStyle("Fingerprint:", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewLabel(formattedFingerprint),
		widget.NewLabel("Verify this with contacts via a second channel"),
	)

	dialog.ShowCustom("My Identity", "Close", content, a.mainWindow)
}

func (a *App) OnMessageReceived(contactID int64, message *database.Message) {
	log.Printf("UI: Message received from contact %d", contactID)

	if a.selectedContact != nil && a.selectedContact.ID == contactID {
		a.loadMessages()
	}

	a.refreshContacts()
}

func (a *App) OnMessageSent(contactID int64, message *database.Message) {
	log.Printf("UI: Message sent to contact %d", contactID)

	if a.selectedContact != nil && a.selectedContact.ID == contactID {
		a.loadMessages()
	}
}

func (a *App) OnContactOnline(contactID int64) {
	log.Printf("UI: Contact %d is online", contactID)

	if a.selectedContact != nil && a.selectedContact.ID == contactID {
		a.statusLabel.SetText("🟢 Online")
	}

	a.refreshContacts()
}

func (a *App) OnContactOffline(contactID int64) {
	log.Printf("UI: Contact %d is offline", contactID)

	if a.selectedContact != nil && a.selectedContact.ID == contactID {
		contact, _ := a.chatManager.GetContact(contactID)
		if contact != nil && contact.LastSeen != nil {
			a.statusLabel.SetText(fmt.Sprintf("Last seen: %s", contact.LastSeen.Format("Jan 02, 15:04")))
		} else {
			a.statusLabel.SetText("⚫ Offline")
		}
	}

	a.refreshContacts()
}

func (a *App) OnError(err error) {
	log.Printf("UI: Error: %v", err)
	dialog.ShowError(err, a.mainWindow)
}

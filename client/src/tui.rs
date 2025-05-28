use crate::{encrypt_data, pad_message, receive_and_fetch_messages, send_encrypted_message};

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};

use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Terminal,
};

use std::{
    io,
    sync::{mpsc::channel, Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

pub fn run_tui(app: MessagingApp) -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let messages = Arc::clone(&app.messages);
    let messages_thread = Arc::clone(&app.messages);
    let app_clone = app.clone();

    thread::spawn(move || loop {
        let room_id = app_clone.shared_room_id.lock().unwrap().clone();
        let url = app_clone.shared_url.lock().unwrap().clone();
        let secret = &*app_clone.shared_hybrid_secret;

        if let Ok(new_msgs) = receive_and_fetch_messages(&room_id, secret, &url, true) {
            let mut msgs = messages_thread.lock().unwrap();
            for msg in new_msgs {
                if !msgs.contains(&msg) {
                    msgs.push(msg);
                }
            }

            const MAX_CACHE_SIZE: usize = 1000;
            let len = msgs.len();
            if len > MAX_CACHE_SIZE {
                msgs.drain(0..(len - MAX_CACHE_SIZE));
            }
        }

        thread::sleep(Duration::from_secs(10));
    });

    let (tx, rx) = channel::<String>();
    let send_app = app.clone();
    let send_messages = Arc::clone(&app.messages);

    thread::spawn(move || {
        for input_msg in rx {
            let formatted = format!("<strong>{}</strong>: {}", send_app.username, input_msg);
            let padded = pad_message(&formatted, 2048);
            let room_id = send_app.shared_room_id.lock().unwrap().clone();
            let url = send_app.shared_url.lock().unwrap().clone();
            let secret = &*send_app.shared_hybrid_secret;

            if let Ok(encrypted) = encrypt_data(&padded, secret) {
                if send_encrypted_message(&encrypted, &room_id, &url).is_ok() {
                    let mut msgs = send_messages.lock().unwrap();
                    msgs.push(formatted);
                }
            }
        }
    });

    let mut input = String::new();
    let mut last_tick = Instant::now();
    let tick_rate = Duration::from_millis(250);
    let mut scroll_offset: usize = 0;
    let mut dark_mode = true;

    loop {
        terminal.draw(|f| {
            let size = f.size();
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints([Constraint::Min(1), Constraint::Length(3)])
                .split(size);

            let msgs = messages.lock().unwrap();
            let list_items: Vec<ListItem> = msgs.iter().map(|m| ListItem::new(parse_message_to_line(m))).collect();

            let visible_height = chunks[0].height.saturating_sub(2) as usize;
            let total_msgs = list_items.len();
            let start = scroll_offset.min(total_msgs.saturating_sub(visible_height));
            let end = (start + visible_height).min(total_msgs);
            let visible_items = list_items[start..end].to_vec();

            let scrollbar = if total_msgs > visible_height {
                let mut bar = vec![' '; visible_height];
                let pos = ((scroll_offset as f64 / total_msgs.max(1) as f64) * visible_height as f64)
                    .round() as usize;
                if let Some(b) = bar.get_mut(pos.min(visible_height - 1)) {
                    *b = '█';
                }
                Some(bar.into_iter().collect::<String>())
            } else {
                None
            };

            let border_color = if dark_mode { Color::Blue } else { Color::DarkGray };
            let input_color = if dark_mode { Color::Yellow } else { Color::Black };
            let background = if dark_mode { Color::Black } else { Color::White };
            let text_color = if dark_mode { Color::White } else { Color::Black };

            let messages_box = List::new(visible_items)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title("\u{1f4e8} Messages")
                        .border_style(Style::default().fg(border_color))
                        .title_style(Style::default().fg(text_color).add_modifier(Modifier::BOLD)),
                )
                .highlight_style(Style::default().bg(Color::DarkGray));
            f.render_widget(messages_box, chunks[0]);

            if let Some(scroll_str) = scrollbar {
                let scrollbar_block = Paragraph::new(scroll_str)
                    .style(Style::default().fg(Color::DarkGray))
                    .block(Block::default());
                let area = ratatui::layout::Rect {
                    x: chunks[0].x + chunks[0].width - 1,
                    y: chunks[0].y + 1,
                    width: 1,
                    height: chunks[0].height.saturating_sub(2),
                };
                f.render_widget(scrollbar_block, area);
            }

            let input_box = Paragraph::new(input.as_str())
                .style(Style::default().fg(input_color).bg(background))
                .block(
                    Block::default()
                        .title("\u{1f4ac} Your Message")
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(border_color))
                        .title_style(Style::default().fg(text_color)),
                );
            f.render_widget(input_box, chunks[1]);
            f.set_cursor(chunks[1].x + input.len() as u16 + 1, chunks[1].y + 1);
        })?;

        let timeout = tick_rate.saturating_sub(last_tick.elapsed());
        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Enter => {
                        if input.trim().eq_ignore_ascii_case("exit") {
                            break;
                        }
                        if !input.trim().is_empty() {
                            let _ = tx.send(input.trim().to_string());
                            input.clear();
                        }
                    }
                    KeyCode::Backspace => { input.pop(); }
                    KeyCode::Char(c) => { input.push(c); }
                    KeyCode::Up => { if scroll_offset > 0 { scroll_offset -= 1; } }
                    KeyCode::Down => {
                        let msgs_len = messages.lock().unwrap().len();
                        if scroll_offset < msgs_len.saturating_sub(1) {
                            scroll_offset += 1;
                        }
                    }
                    KeyCode::PageUp => { scroll_offset = scroll_offset.saturating_sub(5); }
                    KeyCode::PageDown => {
                        scroll_offset = (scroll_offset + 5)
                            .min(messages.lock().unwrap().len().saturating_sub(1));
                    }
                    KeyCode::Tab => { dark_mode = !dark_mode; }
                    KeyCode::Esc => break,
                    _ => {}
                }
            }
        }

        if last_tick.elapsed() >= tick_rate {
            last_tick = Instant::now();
        }
    }

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(())
}

fn parse_message_to_line(msg: &str) -> Line {
    let mut cleaned_msg = msg.to_string();

    for tag in &["media", "audio", "pfp"] {
        while let Some(start) = cleaned_msg.find(&format!("<{}>", tag)) {
            if let Some(end) = cleaned_msg[start..].find(&format!("</{}>", tag)) {
                let end = start + end + tag.len() + 3;
                cleaned_msg.replace_range(start..end, "");
            } else {
                break;
            }
        }
    }

    let mut spans = Vec::new();
    let mut remainder = cleaned_msg.as_str();

    while let Some(start) = remainder.find("<strong>") {
        if start > 0 {
            spans.push(Span::raw(remainder[..start].to_string()));
        }
        if let Some(end) = remainder.find("</strong>") {
            let bold_text = &remainder[start + 8..end];
            spans.push(Span::styled(bold_text.to_string(), Style::default().add_modifier(Modifier::BOLD)));
            remainder = &remainder[end + 9..];
        } else {
            spans.push(Span::raw(remainder.to_string()));
            remainder = "";
            break;
        }
    }

    if !remainder.is_empty() {
        spans.push(Span::raw(remainder.to_string()));
    }

    Line::from(spans)
}

#[derive(Clone)]
pub struct MessagingApp {
    pub username: String,
    pub shared_hybrid_secret: Arc<String>,
    pub shared_room_id: Arc<Mutex<String>>,
    pub shared_url: Arc<Mutex<String>>,
    pub messages: Arc<Mutex<Vec<String>>>,
}

impl MessagingApp {
    pub fn new(
        username: String,
        shared_hybrid_secret: Arc<String>,
        shared_room_id: Arc<Mutex<String>>,
        shared_url: Arc<Mutex<String>>,
    ) -> Self {
        Self {
            username,
            shared_hybrid_secret,
            shared_room_id,
            shared_url,
            messages: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

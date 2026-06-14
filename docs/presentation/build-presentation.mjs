/**
 * Генератор презентации ЕПСОК (PowerPoint)
 * Запуск: npm run build:pptx
 */
import PptxGenJS from 'pptxgenjs';
import { readFileSync, mkdirSync, existsSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';

const __dir = dirname(fileURLToPath(import.meta.url));
const OUT = join(__dir, 'EPSOK-Presentation.pptx');
const LOGO = join(__dir, '../../demo/public/epsok-mark.svg');

const C = {
  navy: '001126',
  blue: '0061D9',
  blueDark: '0050B2',
  red: 'E52E2E',
  white: 'FFFFFF',
  bg: 'F5F5F7',
  panel: 'FFFFFF',
  text: '333333',
  muted: '76767A',
  success: '43A047',
  gold: '996600',
  sidebar: '0A1A33'
};

const pptx = new PptxGenJS();
pptx.layout = 'LAYOUT_16x9';
pptx.author = 'ЕПСОК';
pptx.title = 'ЕПСОК — Единая платформа следственно-оперативной координации';
pptx.subject = 'Презентация проекта';
pptx.lang = 'ru-RU';

function tricolor(slide, y = 0, h = 0.08) {
  const w = 10;
  slide.addShape(pptx.ShapeType.rect, { x: 0, y, w: w / 3, h, fill: { color: C.white }, line: { color: C.white, width: 0 } });
  slide.addShape(pptx.ShapeType.rect, { x: w / 3, y, w: w / 3, h, fill: { color: C.blue }, line: { color: C.blue, width: 0 } });
  slide.addShape(pptx.ShapeType.rect, { x: (2 * w) / 3, y, w: w / 3, h, fill: { color: C.red }, line: { color: C.red, width: 0 } });
}

function footer(slide, n, total) {
  slide.addText('ЕПСОК · Единая платформа следственно-оперативной координации', {
    x: 0.5, y: 5.15, w: 7, h: 0.35, fontSize: 8, color: C.muted, fontFace: 'Arial'
  });
  slide.addText(`${n} / ${total}`, {
    x: 9, y: 5.15, w: 0.8, h: 0.35, fontSize: 8, color: C.muted, align: 'right', fontFace: 'Arial'
  });
}

function titleSlide(slide, title, subtitle, opts = {}) {
  slide.background = { color: C.navy };
  tricolor(slide, 0, 0.06);
  slide.addShape(pptx.ShapeType.roundRect, {
    x: 0.55, y: 0.85, w: 0.75, h: 0.75, rectRadius: 0.12,
    fill: { color: C.sidebar }, line: { color: C.blue, width: 1 }
  });
  slide.addText('⬡', { x: 0.68, y: 0.95, w: 0.5, h: 0.55, fontSize: 22, color: C.blue, align: 'center' });
  slide.addText(title, {
    x: 0.55, y: 1.85, w: 9, h: 1.2, fontSize: opts.titleSize || 36, bold: true,
    color: C.white, fontFace: 'Arial', lineSpacingMultiple: 1.05
  });
  if (subtitle) {
    slide.addText(subtitle, {
      x: 0.55, y: 3.15, w: 8.5, h: 0.9, fontSize: 16, color: 'B8C5D6',
      fontFace: 'Arial', lineSpacingMultiple: 1.2
    });
  }
  if (opts.pill) {
    slide.addShape(pptx.ShapeType.roundRect, {
      x: 0.55, y: 4.35, w: 2.4, h: 0.42, rectRadius: 0.2,
      fill: { color: C.blue, transparency: 75 }, line: { color: C.blue, width: 0.5 }
    });
    slide.addText(opts.pill, { x: 0.65, y: 4.38, w: 2.2, h: 0.36, fontSize: 11, color: C.white, fontFace: 'Arial' });
  }
}

function contentSlide(slide, heading, bullets, opts = {}) {
  slide.background = { color: opts.dark ? C.navy : C.bg };
  tricolor(slide, 0, 0.05);
  const headColor = opts.dark ? C.white : C.navy;
  const bodyColor = opts.dark ? 'D0D8E4' : C.text;
  slide.addText(heading, {
    x: 0.55, y: 0.35, w: 9, h: 0.75, fontSize: 26, bold: true, color: headColor, fontFace: 'Arial'
  });
  slide.addShape(pptx.ShapeType.rect, {
    x: 0.55, y: 1.05, w: 1.2, h: 0.04, fill: { color: C.blue }, line: { width: 0 }
  });
  const items = bullets.map(b => ({ text: b, options: { bullet: true, breakLine: true } }));
  slide.addText(items, {
    x: 0.55, y: 1.25, w: opts.twoCol ? 4.3 : 8.8, h: 3.6,
    fontSize: 14, color: bodyColor, fontFace: 'Arial', paraSpaceAfter: 8, lineSpacingMultiple: 1.15
  });
  if (opts.rightBox) {
    slide.addShape(pptx.ShapeType.roundRect, {
      x: 5.2, y: 1.25, w: 4.3, h: 3.5, rectRadius: 0.08,
      fill: { color: opts.dark ? C.sidebar : C.panel },
      line: { color: opts.dark ? C.blue : 'D9D9DE', width: 0.75 }
    });
    slide.addText(opts.rightBox.title, {
      x: 5.45, y: 1.45, w: 3.8, h: 0.4, fontSize: 13, bold: true,
      color: opts.dark ? C.white : C.blue, fontFace: 'Arial'
    });
    slide.addText(opts.rightBox.lines.map(l => ({ text: l, options: { bullet: true, breakLine: true } })), {
      x: 5.45, y: 1.95, w: 3.8, h: 2.6, fontSize: 12,
      color: opts.dark ? 'C8D4E4' : C.text, fontFace: 'Arial', paraSpaceAfter: 6
    });
  }
  if (opts.quote) {
    slide.addShape(pptx.ShapeType.roundRect, {
      x: 0.55, y: 4.55, w: 8.9, h: 0.55, rectRadius: 0.06,
      fill: { color: C.blue, transparency: opts.dark ? 80 : 92 }, line: { width: 0 }
    });
    slide.addText(opts.quote, {
      x: 0.75, y: 4.62, w: 8.5, h: 0.42, fontSize: 12, italic: true,
      color: opts.dark ? 'A8C4F0' : C.blueDark, fontFace: 'Arial'
    });
  }
}

function moduleSlide(slide, module, tag, features, accent = C.blue) {
  slide.background = { color: C.bg };
  tricolor(slide, 0, 0.05);
  slide.addShape(pptx.ShapeType.roundRect, {
    x: 0.55, y: 0.35, w: 1.15, h: 0.38, rectRadius: 0.15,
    fill: { color: accent, transparency: 88 }, line: { color: accent, width: 0.5 }
  });
  slide.addText(tag, { x: 0.65, y: 0.38, w: 0.95, h: 0.32, fontSize: 9, bold: true, color: accent, fontFace: 'Arial' });
  slide.addText(module, {
    x: 0.55, y: 0.85, w: 9, h: 0.65, fontSize: 24, bold: true, color: C.navy, fontFace: 'Arial'
  });
  const cards = features.slice(0, 4);
  cards.forEach((f, i) => {
    const col = i % 2;
    const row = Math.floor(i / 2);
    const x = 0.55 + col * 4.55;
    const y = 1.65 + row * 1.75;
    slide.addShape(pptx.ShapeType.roundRect, {
      x, y, w: 4.25, h: 1.55, rectRadius: 0.08,
      fill: { color: C.panel }, line: { color: 'D9D9DE', width: 0.75 },
      shadow: { type: 'outer', blur: 6, offset: 2, angle: 90, opacity: 0.12, color: '000000' }
    });
    slide.addShape(pptx.ShapeType.rect, { x, y, w: 0.06, h: 1.55, fill: { color: accent }, line: { width: 0 } });
    slide.addText(f.title, {
      x: x + 0.25, y: y + 0.18, w: 3.85, h: 0.35, fontSize: 13, bold: true, color: C.navy, fontFace: 'Arial'
    });
    slide.addText(f.desc, {
      x: x + 0.25, y: y + 0.55, w: 3.85, h: 0.85, fontSize: 11, color: C.muted, fontFace: 'Arial', lineSpacingMultiple: 1.1
    });
  });
}

function kpiSlide(slide) {
  slide.background = { color: C.navy };
  tricolor(slide, 0, 0.06);
  slide.addText('Целевые показатели к 2032 г.', {
    x: 0.55, y: 0.35, w: 9, h: 0.65, fontSize: 26, bold: true, color: C.white, fontFace: 'Arial'
  });
  const kpis = [
    { label: 'Межвед. запрос', from: '14–45 дн.', to: '1–3 дня', color: C.blue },
    { label: 'Межрег. связи', from: '~12%', to: '≥45%', color: C.success },
    { label: 'Нарушения сроков УПК', from: '~8%', to: '≤2%', color: C.red },
    { label: 'Серийные дела', from: '2–4 нед.', to: '24–72 ч', color: C.gold },
    { label: 'Custody доказательств', from: '~30%', to: '≥95%', color: C.blue }
  ];
  kpis.forEach((k, i) => {
    const x = 0.55 + (i % 3) * 3.1;
    const y = i < 3 ? 1.35 : 3.35;
    const idx = i < 3 ? i : i - 3;
    const xx = 0.55 + idx * 3.1;
    slide.addShape(pptx.ShapeType.roundRect, {
      x: xx, y, w: 2.85, h: 1.75, rectRadius: 0.1,
      fill: { color: C.sidebar }, line: { color: k.color, width: 0.75 }
    });
    slide.addText(k.label, { x: xx + 0.15, y: y + 0.15, w: 2.55, h: 0.35, fontSize: 10, color: 'A8B8CC', fontFace: 'Arial' });
    slide.addText(k.from, { x: xx + 0.15, y: y + 0.55, w: 1.2, h: 0.45, fontSize: 14, color: '8899AA', fontFace: 'Arial', strike: true });
    slide.addText('→', { x: xx + 1.2, y: y + 0.58, w: 0.35, h: 0.4, fontSize: 14, color: k.color, fontFace: 'Arial' });
    slide.addText(k.to, { x: xx + 1.45, y: y + 0.5, w: 1.25, h: 0.55, fontSize: 20, bold: true, color: k.color, fontFace: 'Arial' });
  });
}

function roadmapSlide(slide) {
  slide.background = { color: C.bg };
  tricolor(slide, 0, 0.05);
  slide.addText('Дорожная карта', { x: 0.55, y: 0.35, w: 9, h: 0.65, fontSize: 26, bold: true, color: C.navy, fontFace: 'Arial' });
  const phases = [
    { phase: '0', years: '2026', title: 'Подготовка', desc: 'Концепция · ТЗ · 3 региона' },
    { phase: '1', years: '2027–28', title: 'Пилот', desc: 'MVP · 500 пользователей' },
    { phase: '2', years: '2029–30', title: 'Регионы', desc: '85 субъектов · ФНС/РФМ/ФТС' },
    { phase: '3', years: '2031–32', title: 'Федерация', desc: '100 000 пользователей' },
    { phase: '4', years: '2033–35', title: 'Зрелость', desc: 'AI-ассистент · полная эксплуатация' }
  ];
  phases.forEach((p, i) => {
    const x = 0.45 + i * 1.85;
    slide.addShape(pptx.ShapeType.roundRect, {
      x, y: 1.35, w: 1.65, h: 3.5, rectRadius: 0.08,
      fill: { color: i === 1 ? C.blue : C.panel },
      line: { color: i === 1 ? C.blue : 'D9D9DE', width: 0.75 }
    });
    slide.addText(`Фаза ${p.phase}`, {
      x, y: 1.5, w: 1.65, h: 0.3, fontSize: 9, color: i === 1 ? 'CCE0FF' : C.muted, align: 'center', fontFace: 'Arial'
    });
    slide.addText(p.years, {
      x, y: 1.85, w: 1.65, h: 0.45, fontSize: 16, bold: true, color: i === 1 ? C.white : C.navy, align: 'center', fontFace: 'Arial'
    });
    slide.addText(p.title, {
      x: x + 0.1, y: 2.45, w: 1.45, h: 0.45, fontSize: 12, bold: true, color: i === 1 ? C.white : C.blue, align: 'center', fontFace: 'Arial'
    });
    slide.addText(p.desc, {
      x: x + 0.1, y: 3.05, w: 1.45, h: 1.5, fontSize: 9, color: i === 1 ? 'D8E8FF' : C.muted, align: 'center', fontFace: 'Arial', lineSpacingMultiple: 1.15
    });
    if (i < phases.length - 1) {
      slide.addText('→', { x: x + 1.55, y: 2.6, w: 0.35, h: 0.4, fontSize: 16, color: C.blue, fontFace: 'Arial' });
    }
  });
}

function closingSlide(slide) {
  slide.background = { color: C.navy };
  tricolor(slide, 0, 0.06);
  slide.addText('Интерактивный прототип', {
    x: 0.55, y: 1.2, w: 9, h: 0.55, fontSize: 14, color: '8899AA', fontFace: 'Arial'
  });
  slide.addText('Демонстрация интерфейса', {
    x: 0.55, y: 1.75, w: 9, h: 0.85, fontSize: 32, bold: true, color: C.white, fontFace: 'Arial'
  });
  slide.addShape(pptx.ShapeType.roundRect, {
    x: 0.55, y: 2.85, w: 5.5, h: 1.65, rectRadius: 0.1,
    fill: { color: C.sidebar }, line: { color: C.blue, width: 1 }
  });
  slide.addText([
    { text: 'URL: ', options: { bold: true, color: '8899AA' } },
    { text: 'http://localhost:3000', options: { color: C.blue, bold: true } }
  ], { x: 0.8, y: 3.05, w: 5, h: 0.4, fontSize: 14, fontFace: 'Arial' });
  slide.addText([
    { text: 'Демо: ', options: { bold: true, color: '8899AA' } },
    { text: 'ivanov.sp / epsok2028', options: { color: C.white } }
  ], { x: 0.8, y: 3.55, w: 5, h: 0.4, fontSize: 14, fontFace: 'Arial' });
  slide.addText([
    { text: 'Тех. админ: ', options: { bold: true, color: '8899AA' } },
    { text: 'sidorov.av / epsok2028', options: { color: C.white } }
  ], { x: 0.8, y: 3.95, w: 5, h: 0.4, fontSize: 14, fontFace: 'Arial' });
  slide.addText('ЕПСОК не заменяет ГИАЦ и СОДЧ — надстраивается над ведомственными системами через СМЭВ', {
    x: 0.55, y: 4.85, w: 9, h: 0.45, fontSize: 11, italic: true, color: '778899', fontFace: 'Arial'
  });
}

const TOTAL = 14;
let n = 0;

// 1
let s = pptx.addSlide();
titleSlide(s, 'ЕПСОК', 'Единая платформа следственно-оперативной координации', {
  pill: 'Пилот · Краснодарский край · 2028',
  titleSize: 40
});
s.addText('Повышение раскрываемости преступлений\nчерез межведомственную цифровизацию', {
  x: 0.55, y: 4.0, w: 8, h: 0.7, fontSize: 13, color: '8899AA', fontFace: 'Arial'
});
footer(s, ++n, TOTAL);

// 2
s = pptx.addSlide();
contentSlide(s, 'Проблема', [
  '15+ ведомственных ИС без единого контура расследования',
  'Межведомственный обмен — 14–45 рабочих дней',
  'Серийные преступления не видны на федеральном уровне',
  '~8% дел — нарушения процессуальных сроков (УПК)',
  '~70% цифровых доказательств без полной цепочки custody'
], { quote: '«Следователь во Владивостоке не видит связь с делом в Калининграде»' });
footer(s, ++n, TOTAL);

// 3
s = pptx.addSlide();
contentSlide(s, 'Решение — платформа-надстройка', [
  'Сквозная карточка расследования и рабочая группа',
  'Граф связей: лица, счета, телефоны, организации',
  'Цифровой конвейер запросов — 1–3 рабочих дня',
  'Реестр доказательств с неизменяемым журналом (WORM)',
  'Контроль сроков УПК и федеральная аналитика modus operandi'
], {
  rightBox: {
    title: 'Не заменяет',
    lines: ['ГИАЦ · СОДЧ', 'ИС СК РФ · ФСБ', 'Интеграция через СМЭВ']
  },
  quote: 'ЕПСОК — хаб координации, а не дублирование ведомственных баз'
});
footer(s, ++n, TOTAL);

// 4
s = pptx.addSlide();
contentSlide(s, 'Экосистема участников', [
  'МВД России — методология, пилот, адаптер ГИАЦ',
  'СК РФ — следственный контур, экспертизы',
  'Генпрокуратура — надзор, сроки УПК',
  'Минцифры — оператор СМЭВ, ЦОД',
  'ФНС · РФМ · ФТС · ФСИН · ФССП — исполнители запросов'
], { twoCol: false, dark: true });
footer(s, ++n, TOTAL);

// 5
s = pptx.addSlide();
moduleSlide(s, 'Дашборд и реестр дел', 'СЛЕДСТВИЕ', [
  { title: 'KPI в реальном времени', desc: 'Дела, сроки, запросы, OSINT, сигналы «Горизонт»' },
  { title: 'Каскадный фильтр ПОЛ-001', desc: 'Регион → ведомство → отдел — только свои дела' },
  { title: 'Карточка дела', desc: 'Хронология, участники, смежные дела, документы' },
  { title: '36 ролей демо', desc: 'Следователь, руководитель, прокурор, исполнитель, аналитик' }
]);
footer(s, ++n, TOTAL);

// 6
s = pptx.addSlide();
moduleSlide(s, 'Граф связей', 'АНАЛИТИКА', [
  { title: 'Изолированный контур', desc: 'Каждое дело — отдельный граф, без автослияния' },
  { title: 'Коммуникации', desc: 'Вызовы и SMS с быстрой проверкой по ГИАЦ (ПОЛ-007)' },
  { title: 'Импорт из OSINT', desc: 'Находки → узлы графа с подтверждением ФИО' },
  { title: 'Федеральные связи', desc: 'Смежные дела по счёту, SIM, IBAN — кластер МВ-2847' }
], C.blueDark);
footer(s, ++n, TOTAL);

// 7
s = pptx.addSlide();
moduleSlide(s, 'Межведомственные запросы', 'ОБМЕН ДАННЫМИ', [
  { title: '3 уровня', desc: 'Межвед (СМЭВ) · внутри ведомства · внутри отдела' },
  { title: '15 ведомств', desc: 'ФНС, РФМ, ФТС, ФСБ, Росгвардия, суды и др.' },
  { title: 'SLA', desc: 'От 4 часов (отдел) до 3 рабочих дней (межвед)' },
  { title: 'Правовое основание', desc: 'Каждый запрос — постановление, журнал аудита' }
], C.success);
footer(s, ++n, TOTAL);

// 8
s = pptx.addSlide();
moduleSlide(s, 'Открытые источники (OSINT)', 'ПОЛ-006', [
  { title: 'Изолированный контур', desc: 'Whitelist модулей, без прямого доступа к делам' },
  { title: 'Профили сбора', desc: 'Пассивный · расширенный · углублённый' },
  { title: 'Пакеты доказательств', desc: 'SHA-256 · неизменяемая запись · custody chain' },
  { title: 'WORM-аудит', desc: 'Все действия фиксируются, purge по регламенту' }
], C.gold);
footer(s, ++n, TOTAL);

// 9
s = pptx.addSlide();
moduleSlide(s, 'Горизонт — федеральная аналитика', 'ПОЛ-007', [
  { title: 'Serendipity Engine', desc: 'Неожиданные совпадения между делами' },
  { title: 'Ghost Link Detector', desc: 'Скрытые связи через обезличенные паттерны' },
  { title: 'Investigation Twin', desc: 'Цифровой двойник расследования' },
  { title: 'Без гражданской БД', desc: 'Хеши телефонов и счетов — не ФИО граждан' }
], '7C3AED');
footer(s, ++n, TOTAL);

// 10
s = pptx.addSlide();
contentSlide(s, 'Защищённая корпоративная почта', [
  'Сквозное шифрование: 4–6 уровней AES-256-GCM + HMAC',
  'ГОСТ Р 34.12-2015 · ГОСТ TLS 1.3 · HSM',
  'Грифы: стандарт · служебное · ДСП',
  'Шифрование на клиенте до отправки — в хранилище только шифротекст',
  'Адресная книга ведомств · ответы и цепочки переписки'
], { dark: true, rightBox: { title: 'Тех. контур', lines: ['Только тех. админ видит параметры шифрования', 'Следователь — защищённый канал без деталей'] } });
footer(s, ++n, TOTAL);

// 11
s = pptx.addSlide();
contentSlide(s, 'Модель информационной безопасности', [
  'Zero Trust · ABAC · принцип наименьших привилегий',
  'Сессии: PBKDF2 120k · AES-256-GCM · HMAC-SHA-256',
  'WORM-журнал аудита — append-only, подписанные записи',
  'Тех. админ ЦОД не видит содержимое дел (ПОЛ-008)',
  '187-ФЗ КИИ · ФСТЭК · УЗ-1 · данные только в РФ'
], {
  dark: true,
  quote: 'Red team · ГосСОПКА · DLP · SIEM · UEBA'
});
footer(s, ++n, TOTAL);

// 12
s = pptx.addSlide();
kpiSlide(s);
footer(s, ++n, TOTAL);

// 13
s = pptx.addSlide();
roadmapSlide(s);
footer(s, ++n, TOTAL);

// 14
s = pptx.addSlide();
closingSlide(s);
footer(s, ++n, TOTAL);

await pptx.writeFile({ fileName: OUT });
console.log('✓ Презентация сохранена:', OUT);

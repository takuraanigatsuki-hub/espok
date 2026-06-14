const titles = {
  dashboard: 'Дашборд руководителя',
  case: 'Карточка расследования',
  graph: 'Граф связей',
  requests: 'Запросы данных',
  agencies: 'Ведомства',
  osint: 'Открытые источники',
  horizon: 'Горизонт',
  admin: 'Тех. администрирование',
  func_admin: 'Управление ИТ ведомства',
  deadlines: 'Контроль сроков УПК',
  cases: 'Реестр дел',
  help: 'Справка',
  regulations: 'Регламенты',
  support: 'Поддержка',
  profile: 'Личное дело',
  staff: 'Сотрудники',
  suspects: 'Дела фигурантов',
  mail: 'Корпоративная почта'
};

const utilViews = ['help', 'regulations', 'support'];

const AUTH_STORAGE_KEY = 'epsok-session';
const AUTH_REMEMBER_KEY = 'epsok-session-persistent';
const ACTIVE_VIEW_KEY = 'epsok-active-view';

const authUsers = {
  'ivanov.sp': {
    personaId: 'INV_MVD',
    displayName: 'Иванов С.П.',
    contourLabel: 'Следственный комитет · Краснодарский край'
  },
  'sidorov.av': {
    personaId: 'TECH_ADMIN',
    displayName: 'Сидоров А.В.',
    contourLabel: 'Тех. контур · ЦОД'
  },
  'kozlov.va': {
    personaId: 'FUNC_ADMIN',
    displayName: 'Козлов В.А.',
    contourLabel: 'ИТ контур · МВД России'
  }
};

const ROLE_VIEWS = {
  inv: ['dashboard', 'cases', 'case', 'graph', 'requests', 'agencies', 'osint', 'deadlines', 'profile', 'suspects', 'mail'],
  inv_lead: ['dashboard', 'cases', 'case', 'graph', 'requests', 'agencies', 'osint', 'horizon', 'deadlines', 'profile', 'staff', 'suspects', 'mail'],
  ops: ['dashboard', 'cases', 'case', 'graph', 'requests', 'agencies', 'osint', 'deadlines', 'profile', 'suspects', 'mail'],
  prosecutor: ['dashboard', 'cases', 'case', 'deadlines', 'horizon', 'agencies', 'profile', 'suspects', 'mail'],
  prosecutor_mil: ['dashboard', 'cases', 'case', 'deadlines', 'agencies', 'profile', 'suspects', 'mail'],
  executor: ['dashboard', 'requests', 'agencies', 'profile', 'mail'],
  analyst: ['dashboard', 'cases', 'case', 'graph', 'horizon', 'agencies', 'profile', 'mail'],
  court: ['dashboard', 'cases', 'case', 'deadlines', 'agencies', 'profile', 'mail'],
  admin: ['admin', 'profile', 'staff', 'mail'],
  func_admin: ['admin', 'profile', 'staff', 'mail']
};

function canCreateRequest(p = getActivePersona()) {
  return !!getAgencyPolicy(p).canCreate;
}

function canRunOsint(p = getActivePersona()) {
  return canLaunchOsintScan(p);
}

function canViewOsint(p = getActivePersona()) {
  return p.allowedViews.includes('osint');
}

function getOsintTier(p = getActivePersona()) {
  if (!canViewOsint(p)) return 'none';
  if (['inv', 'inv_lead'].includes(p.roleType)) return 'investigator';
  if (p.roleType === 'ops') return 'operative';
  if (['prosecutor', 'prosecutor_mil'].includes(p.roleType)) return 'supervisory';
  return 'readonly';
}

function canLaunchOsintScan(p = getActivePersona()) {
  return ['investigator', 'operative'].includes(getOsintTier(p));
}

function canCreateEvidencePackage(p = getActivePersona()) {
  return canLaunchOsintScan(p);
}

function syncCapabilityButtons(p = getActivePersona()) {
  document.querySelector('.cases-new-btn')?.classList.toggle('hidden', !canCreateCase());
  document.getElementById('requests-new-btn')?.classList.toggle('hidden', !canCreateRequest(p));
  const canLaunch = canLaunchOsintScan(p);
  const canView = canViewOsint(p);
  document.querySelectorAll('#osint-form input, #osint-form select, #osint-form button[type="submit"]').forEach(el => {
    el.disabled = !canLaunch;
  });
  document.querySelectorAll('.osint-create-evidence-btn').forEach(el => {
    el.classList.toggle('hidden', !canCreateEvidencePackage(p));
  });
  const osintHint = document.getElementById('osint-role-hint');
  if (osintHint) {
    osintHint.classList.toggle('hidden', canLaunch || !canView);
    if (canView && !canLaunch) {
      osintHint.textContent = 'Надзорный контур · просмотр проверок и пакетов · запуск недоступен (ПОЛ-006)';
    }
  }
}

function canAccessView(viewId, p = getActivePersona()) {
  return p.allowedViews.includes(viewId);
}

function isCaseReadOnly(p = getActivePersona(), caseId = activeCaseId) {
  if (caseId && !personaCanAccessCase(caseId)) return true;
  return ['prosecutor', 'prosecutor_mil', 'analyst', 'court'].includes(p.roleType);
}

function renderCaseQuickLinksHtml(c) {
  const p = getActivePersona();
  const btns = [];
  if (canAccessView('graph', p)) {
    btns.push(`<button type="button" class="btn-sm case-quick-link" onclick="openCaseGraph('${c.id}')"><span class="case-quick-icon" aria-hidden="true">◎</span> Граф связей</button>`);
  }
  if (canAccessView('deadlines', p)) {
    btns.push(`<button type="button" class="btn-sm case-quick-link" onclick="activeCaseId='${c.id}';showView('deadlines')"><span class="case-quick-icon" aria-hidden="true">⏱</span> Сроки УПК</button>`);
  }
  if (canAccessView('horizon', p)) {
    btns.push(`<button type="button" class="btn-sm case-quick-link" onclick="selectHorizonCase('${c.id}');showView('horizon')"><span class="case-quick-icon" aria-hidden="true">◈</span> Горизонт</button>`);
  }
  if (canViewOsint(p)) {
    btns.push(`<button type="button" class="btn-sm case-quick-link" onclick="activeCaseId='${c.id}';showView('osint')"><span class="case-quick-icon" aria-hidden="true">⌕</span> Открытые источники</button>`);
    if (canLaunchOsintScan(p)) {
      btns.push(`<button type="button" class="btn-sm case-quick-link" onclick="scrollToEvidencePackages()"><span class="case-quick-icon" aria-hidden="true">▣</span> Пакеты доказательств</button>`);
    }
  }
  if (!btns.length) return '';
  return `<div class="case-quick-links">${btns.join('')}</div>`;
}

function buildAllowedViews(roleType, extras = [], deny = []) {
  const base = ROLE_VIEWS[roleType] || ROLE_VIEWS.inv;
  return [...new Set([...base, ...extras])].filter(v => !deny.includes(v));
}

function enrichPersona(p) {
  return {
    ...p,
    allowedViews: buildAllowedViews(p.roleType, p.accessExtras, p.accessDeny)
  };
}

const demoPersonas = {
  INV_MVD: enrichPersona({
    id: 'INV_MVD',
    roleType: 'inv',
    group: 'МВД России',
    avatar: 'ИС',
    name: 'Иванов С.П.',
    role: 'Следователь · СО №3',
    department: 'СО №3 по Центральному району',
    agency: 'МВД',
    region: 'Краснодарский край',
    headerContour: 'Следственный комитет',
    contourSub: 'Краснодарский край · СО №3 · МВД',
    dashboardTitle: 'Дашборд следователя',
    dashboardMode: 'investigator',
    defaultView: 'dashboard',
    caseScope: { agency: 'МВД', region: 'Краснодарский край', department: 'СО №3 по Центральному району' }
  }),
  OPS_MVD: enrichPersona({
    id: 'OPS_MVD',
    roleType: 'ops',
    group: 'МВД России',
    avatar: 'ОУ',
    name: 'Сидоров М.В.',
    role: 'Оперуполномоченный · ОУР',
    department: 'ОУР №4',
    agency: 'МВД',
    region: 'Ставропольский край',
    headerContour: 'Опер. контур',
    contourSub: 'Ставропольский край · ОУР №4 · МВД',
    dashboardTitle: 'Опер. дашборд',
    dashboardMode: 'investigator',
    defaultView: 'graph',
    caseScope: { agency: 'МВД' }
  }),
  INV_LEAD_MVD: enrichPersona({
    id: 'INV_LEAD_MVD',
    roleType: 'inv_lead',
    group: 'МВД России',
    avatar: 'РС',
    name: 'Морозова Е.А.',
    role: 'Руководитель СО',
    department: 'СО №1 по Прикубанскому району',
    agency: 'МВД',
    region: 'Краснодарский край',
    headerContour: 'Следственный комитет',
    contourSub: 'Краснодарский край · руководитель · МВД',
    dashboardTitle: 'Дашборд руководителя',
    dashboardMode: 'investigator',
    defaultView: 'dashboard',
    isManager: true,
    caseScope: { agency: 'МВД', region: 'Краснодарский край' }
  }),
  OPS_LEAD_MVD: enrichPersona({
    id: 'OPS_LEAD_MVD',
    roleType: 'inv_lead',
    group: 'МВД России',
    avatar: 'РО',
    name: 'Никитин Р.О.',
    role: 'Руководитель ОУР',
    department: 'ОУР №4',
    agency: 'МВД',
    region: 'Ставропольский край',
    headerContour: 'Следственный комитет',
    contourSub: 'Ставропольский край · руководитель · МВД',
    dashboardTitle: 'Дашборд руководителя',
    dashboardMode: 'investigator',
    defaultView: 'dashboard',
    isManager: true,
    caseScope: { agency: 'МВД', region: 'Ставропольский край' }
  }),
  INV_SK: enrichPersona({
    id: 'INV_SK',
    roleType: 'inv',
    group: 'СК РФ',
    avatar: 'ПА',
    name: 'Петрова А.К.',
    role: 'Следователь · СУ',
    department: 'СУ по ЮВАО',
    agency: 'СК',
    region: 'Москва',
    headerContour: 'Следственный комитет',
    contourSub: 'Москва · СУ ЮВАО · СК РФ',
    dashboardTitle: 'Дашборд следователя СК',
    dashboardMode: 'investigator',
    accessExtras: ['horizon'],
    defaultView: 'cases',
    caseScope: { agency: 'СК', region: 'Москва' }
  }),
  INV_LEAD_SK: enrichPersona({
    id: 'INV_LEAD_SK',
    roleType: 'inv_lead',
    group: 'СК РФ',
    avatar: 'РС',
    name: 'Смирнов Д.А.',
    role: 'Руководитель СУ',
    department: 'СУ по ЮВАО',
    agency: 'СК',
    region: 'Москва',
    headerContour: 'Следственный комитет',
    contourSub: 'Москва · руководитель · СК РФ',
    dashboardTitle: 'Дашборд руководителя',
    dashboardMode: 'investigator',
    defaultView: 'dashboard',
    isManager: true,
    caseScope: { agency: 'СК', region: 'Москва' }
  }),
  INV_FSB: enrichPersona({
    id: 'INV_FSB',
    roleType: 'inv',
    group: 'ФСБ России',
    avatar: 'ФС',
    name: 'Волков И.Н.',
    role: 'Следователь · УФСБ',
    department: 'УФСБ по Краснодарскому краю',
    agency: 'ФСБ',
    region: 'Краснодарский край',
    headerContour: 'Оперативный контур',
    contourSub: 'Краснодарский край · УФСБ · ФСБ',
    dashboardTitle: 'Дашборд следователя ФСБ',
    dashboardMode: 'investigator',
    accessDeny: ['horizon'],
    defaultView: 'cases',
    caseScope: { agency: 'ФСБ' }
  }),
  PROSEC: enrichPersona({
    id: 'PROSEC',
    roleType: 'prosecutor',
    group: 'Прокуратура РФ',
    avatar: 'ПР',
    name: 'Кузнецова Л.В.',
    role: 'Прокурор',
    department: 'Прокуратура Краснодарского края',
    agency: 'PROSECUTOR',
    region: 'Краснодарский край',
    headerContour: 'Надзорный контур',
    contourSub: 'Краснодарский край · прокуратура',
    dashboardTitle: 'Надзорный контур',
    dashboardMode: 'prosecutor',
    defaultView: 'deadlines',
    caseScope: { region: 'Краснодарский край' }
  }),
  PROSEC_MIL: enrichPersona({
    id: 'PROSEC_MIL',
    roleType: 'prosecutor_mil',
    group: 'Военная прокуратура',
    avatar: 'ВП',
    name: 'Баранов К.Г.',
    role: 'Военный прокурор',
    department: 'Военная прокуратура ЮВО',
    agency: 'MILPROSEC',
    region: 'Ростовская область',
    headerContour: 'Надзорный контур',
    contourSub: 'ЮВО · военная прокуратура',
    dashboardTitle: 'Надзор · ВС РФ',
    dashboardMode: 'prosecutor',
    defaultView: 'deadlines',
    caseScope: { region: 'Ростовская область' }
  }),
  INV_RGV: enrichPersona({
    id: 'INV_RGV',
    roleType: 'inv',
    group: 'Росгвардия',
    avatar: 'РГ',
    name: 'Кравцов А.Л.',
    role: 'Следователь · Росгвардия',
    department: 'Управление Росгвардии',
    agency: 'РОСГВАРДИЯ',
    region: 'Ставропольский край',
    headerContour: 'Следственный комитет',
    contourSub: 'Ставропольский край · Росгвардия',
    dashboardTitle: 'Дашборд следователя',
    dashboardMode: 'investigator',
    defaultView: 'cases',
    caseScope: { agency: 'РОСГВАРДИЯ' }
  }),
  INV_FTS: enrichPersona({
    id: 'INV_FTS',
    roleType: 'inv',
    group: 'ФТС России',
    avatar: 'ТМ',
    name: 'Новикова Е.В.',
    role: 'Следователь · таможня',
    department: 'Таможня Шереметьево',
    agency: 'ФТС',
    region: 'Москва',
    headerContour: 'Следственный комитет',
    contourSub: 'Москва · ФТС · контрабанда',
    dashboardTitle: 'Дашборд таможни',
    dashboardMode: 'investigator',
    defaultView: 'cases',
    caseScope: { agency: 'ФТС' }
  }),
  EXEC_FSIN: enrichPersona({
    id: 'EXEC_FSIN',
    roleType: 'executor',
    group: 'ФСИН России',
    avatar: 'УИ',
    name: 'Орлова М.С.',
    role: 'Исполнитель запросов',
    department: 'Управление по КК',
    agency: 'FSIN',
    region: 'Краснодарский край',
    headerContour: 'Исполнительный контур',
    contourSub: 'ФСИН · УИС · Краснодарский край',
    dashboardTitle: 'Очередь запросов УИС',
    dashboardMode: 'executor',
    defaultView: 'requests',
    execAgency: 'ФСИН'
  }),
  EXEC_FTS: enrichPersona({
    id: 'EXEC_FTS',
    roleType: 'executor',
    group: 'ФТС России',
    avatar: 'ТИ',
    name: 'Зайцев Р.О.',
    role: 'Исполнитель · таможня',
    department: 'Центральное таможенное управление',
    agency: 'FTS_EXEC',
    region: 'Федеральный',
    headerContour: 'Исполнительный контур',
    contourSub: 'ФТС · очередь СМЭВ',
    dashboardTitle: 'Очередь запросов',
    dashboardMode: 'executor',
    defaultView: 'requests',
    execAgency: 'ФТС'
  }),
  EXEC_ROSREESTR: enrichPersona({
    id: 'EXEC_ROSREESTR',
    roleType: 'executor',
    group: 'Росреестр',
    avatar: 'РР',
    name: 'Павлова Н.И.',
    role: 'Исполнитель запросов',
    department: 'Федеральная служба регистрации',
    agency: 'ROSREESTR',
    region: 'Федеральный',
    headerContour: 'Исполнительный контур',
    contourSub: 'Росреестр · ЕГРН',
    dashboardTitle: 'Очередь выписок',
    dashboardMode: 'executor',
    defaultView: 'requests',
    execAgency: 'Росреестр'
  }),
  COURT_CLERK: enrichPersona({
    id: 'COURT_CLERK',
    roleType: 'court',
    group: 'Суды РФ',
    avatar: 'СУ',
    name: 'Ильина В.П.',
    role: 'Секретарь судебного заседания',
    department: 'Краснодарский краевой суд',
    agency: 'COURT',
    region: 'Краснодарский край',
    headerContour: 'Судебный контур',
    contourSub: 'Краснодарский край · ГАС Правосудие',
    dashboardTitle: 'Судебный контур',
    dashboardMode: 'prosecutor',
    defaultView: 'deadlines',
    caseScope: { region: 'Краснодарский край' }
  }),
  EXEC_CBR: enrichPersona({
    id: 'EXEC_CBR',
    roleType: 'executor',
    group: 'Центральный банк',
    avatar: 'ЦБ',
    name: 'Медведев О.А.',
    role: 'Исполнитель · ПОД/ФТ',
    department: 'Департамент финансового мониторинга',
    agency: 'CBR',
    region: 'Федеральный',
    headerContour: 'Исполнительный контур',
    contourSub: 'ЦБ · запросы через РФМ',
    dashboardTitle: 'Очередь запросов',
    dashboardMode: 'executor',
    defaultView: 'requests',
    execAgency: 'ЦБ'
  }),
  EXEC_RFM: enrichPersona({
    id: 'EXEC_RFM',
    roleType: 'executor',
    group: 'Росфинмониторинг',
    avatar: 'РФ',
    name: 'Никитин П.О.',
    role: 'Исполнитель запросов',
    department: 'Операционный департамент',
    agency: 'RFM',
    region: 'Федеральный',
    headerContour: 'Исполнительный контур',
    contourSub: 'Росфинмониторинг · очередь СМЭВ',
    dashboardTitle: 'Очередь запросов',
    dashboardMode: 'executor',
    defaultView: 'requests',
    execAgency: 'Росфинмониторинг'
  }),
  EXEC_FNS: enrichPersona({
    id: 'EXEC_FNS',
    roleType: 'executor',
    group: 'ФНС России',
    avatar: 'ФН',
    name: 'Егорова Т.С.',
    role: 'Исполнитель запросов',
    department: 'Межрегиональная инспекция',
    agency: 'FNS',
    region: 'Федеральный',
    headerContour: 'Исполнительный контур',
    contourSub: 'ФНС России · очередь СМЭВ',
    dashboardTitle: 'Очередь запросов',
    dashboardMode: 'executor',
    defaultView: 'requests',
    execAgency: 'ФНС'
  }),
  EXEC_MVD: enrichPersona({
    id: 'EXEC_MVD',
    roleType: 'executor',
    group: 'МВД России',
    avatar: 'ГИ',
    name: 'Громов В.А.',
    role: 'Исполнитель · ГИАЦ',
    department: 'ГИАЦ · Краснодарский край',
    agency: 'MVD_EXEC',
    region: 'Краснодарский край',
    headerContour: 'Исполнительный контур',
    contourSub: 'МВД · ГИАЦ · Краснодарский край',
    dashboardTitle: 'Очередь запросов',
    dashboardMode: 'executor',
    defaultView: 'requests',
    execAgency: 'МВД (ГИАЦ)'
  }),
  EXEC_FSSP: enrichPersona({
    id: 'EXEC_FSSP',
    roleType: 'executor',
    group: 'ФССП России',
    avatar: 'СП',
    name: 'Лазарев Д.К.',
    role: 'Судебный пристав · ИО',
    department: 'Отдел судебных приставов №1',
    agency: 'FSSP',
    region: 'Краснодарский край',
    headerContour: 'Исполнительный контур',
    contourSub: 'ФССП · Краснодарский край',
    dashboardTitle: 'Очередь исполнительных листов',
    dashboardMode: 'executor',
    defaultView: 'requests',
    execAgency: 'ФССП'
  }),
  ANALYST: enrichPersona({
    id: 'ANALYST',
    roleType: 'analyst',
    group: 'Аналитический центр',
    avatar: 'АН',
    name: 'Фёдоров А.Н.',
    role: 'Аналитик',
    department: 'Федеральный аналитический контур',
    agency: 'ANALYST',
    region: 'Федеральный',
    headerContour: 'Аналитический контур',
    contourSub: 'Обезличенные данные · федеральный охват',
    dashboardTitle: 'Аналитический контур',
    dashboardMode: 'analyst',
    defaultView: 'horizon',
    caseScope: null
  }),
  INV_MVD_NOVIKOV: enrichPersona({
    id: 'INV_MVD_NOVIKOV',
    roleType: 'inv',
    group: 'МВД России',
    avatar: 'НП',
    name: 'Новиков П.С.',
    role: 'Следователь · СО №2',
    department: 'СО №2 по Карасунскому округу',
    agency: 'МВД',
    region: 'Краснодарский край',
    headerContour: 'Следственный комитет',
    contourSub: 'Краснодарский край · СО №2 · МВД',
    dashboardTitle: 'Дашборд следователя',
    dashboardMode: 'investigator',
    defaultView: 'cases',
    caseScope: { agency: 'МВД', region: 'Краснодарский край', department: 'СО №2 по Карасунскому округу' }
  }),
  INV_MVD_KOVALEV: enrichPersona({
    id: 'INV_MVD_KOVALEV',
    roleType: 'inv',
    group: 'МВД России',
    avatar: 'КД',
    name: 'Ковалёв Д.М.',
    role: 'Следователь · СО №3',
    department: 'СО №3 по Центральному району',
    agency: 'МВД',
    region: 'Краснодарский край',
    headerContour: 'Следственный комитет',
    contourSub: 'Краснодарский край · СО №3 · МВД',
    dashboardTitle: 'Дашборд следователя',
    dashboardMode: 'investigator',
    defaultView: 'dashboard',
    caseScope: { agency: 'МВД', region: 'Краснодарский край', department: 'СО №3 по Центральному району' }
  }),
  INV_MVD_SEMYONOVA: enrichPersona({
    id: 'INV_MVD_SEMYONOVA',
    roleType: 'inv',
    group: 'МВД России',
    avatar: 'СО',
    name: 'Семёнова О.Г.',
    role: 'Следователь · СО №7',
    department: 'СО №7 по Западному округу',
    agency: 'МВД',
    region: 'Краснодарский край',
    headerContour: 'Следственный комитет',
    contourSub: 'Краснодарский край · СО №7 · МВД',
    dashboardTitle: 'Дашборд следователя',
    dashboardMode: 'investigator',
    defaultView: 'cases',
    caseScope: { agency: 'МВД', region: 'Краснодарский край', department: 'СО №7 по Западному округу' }
  }),
  INV_LEAD_MVD_WEST: enrichPersona({
    id: 'INV_LEAD_MVD_WEST',
    roleType: 'inv_lead',
    group: 'МВД России',
    avatar: 'ФН',
    name: 'Федорова Н.С.',
    role: 'Руководитель СО №7',
    department: 'СО №7 по Западному округу',
    agency: 'МВД',
    region: 'Краснодарский край',
    headerContour: 'Следственный комитет',
    contourSub: 'Краснодарский край · руководитель СО №7 · МВД',
    dashboardTitle: 'Дашборд руководителя',
    dashboardMode: 'investigator',
    defaultView: 'dashboard',
    isManager: true,
    caseScope: { agency: 'МВД', region: 'Краснодарский край', department: 'СО №7 по Западному округу' }
  }),
  INV_MVD_ROSTOV: enrichPersona({
    id: 'INV_MVD_ROSTOV',
    roleType: 'inv',
    group: 'МВД России',
    avatar: 'ТА',
    name: 'Тихонов А.Р.',
    role: 'Следователь · ОЭБ и ПК',
    department: 'ОЭБ и ПК',
    agency: 'МВД',
    region: 'Ростовская область',
    headerContour: 'Следственный комитет',
    contourSub: 'Ростовская область · ОЭБ и ПК · МВД',
    dashboardTitle: 'Дашборд следователя',
    dashboardMode: 'investigator',
    defaultView: 'cases',
    caseScope: { agency: 'МВД', region: 'Ростовская область' }
  }),
  OPS_MVD_2: enrichPersona({
    id: 'OPS_MVD_2',
    roleType: 'ops',
    group: 'МВД России',
    avatar: 'АК',
    name: 'Абрамов К.Д.',
    role: 'Оперуполномоченный · ОУР',
    department: 'ОУР №4',
    agency: 'МВД',
    region: 'Ставропольский край',
    headerContour: 'Опер. контур',
    contourSub: 'Ставропольский край · ОУР №4 · МВД',
    dashboardTitle: 'Опер. дашборд',
    dashboardMode: 'investigator',
    defaultView: 'graph',
    caseScope: { agency: 'МВД', region: 'Ставропольский край' }
  }),
  OPS_MVD_3: enrichPersona({
    id: 'OPS_MVD_3',
    roleType: 'ops',
    group: 'МВД России',
    avatar: 'ЧЕ',
    name: 'Чернова Е.В.',
    role: 'Оперуполномоченный · ОУР',
    department: 'ОУР №4',
    agency: 'МВД',
    region: 'Ставропольский край',
    headerContour: 'Опер. контур',
    contourSub: 'Ставропольский край · ОУР №4 · МВД',
    dashboardTitle: 'Опер. дашборд',
    dashboardMode: 'investigator',
    defaultView: 'graph',
    caseScope: { agency: 'МВД', region: 'Ставропольский край' }
  }),
  INV_SK_2: enrichPersona({
    id: 'INV_SK_2',
    roleType: 'inv',
    group: 'СК РФ',
    avatar: 'ГМ',
    name: 'Григорьева М.Н.',
    role: 'Следователь · СУ',
    department: 'СУ по ЮВАО',
    agency: 'СК',
    region: 'Москва',
    headerContour: 'Следственный комитет',
    contourSub: 'Москва · СУ ЮВАО · СК РФ',
    dashboardTitle: 'Дашборд следователя СК',
    dashboardMode: 'investigator',
    accessExtras: ['horizon'],
    defaultView: 'cases',
    caseScope: { agency: 'СК', region: 'Москва' }
  }),
  INV_SK_3: enrichPersona({
    id: 'INV_SK_3',
    roleType: 'inv',
    group: 'СК РФ',
    avatar: 'БА',
    name: 'Борисов А.С.',
    role: 'Следователь · СУ',
    department: 'СУ по ЮВАО',
    agency: 'СК',
    region: 'Москва',
    headerContour: 'Следственный комитет',
    contourSub: 'Москва · СУ ЮВАО · СК РФ',
    dashboardTitle: 'Дашборд следователя СК',
    dashboardMode: 'investigator',
    defaultView: 'dashboard',
    caseScope: { agency: 'СК', region: 'Москва' }
  }),
  INV_LEAD_SK_ROSTOV: enrichPersona({
    id: 'INV_LEAD_SK_ROSTOV',
    roleType: 'inv_lead',
    group: 'СК РФ',
    avatar: 'ЕП',
    name: 'Ефимов П.Л.',
    role: 'Руководитель СУ',
    department: 'СУ по Ленинскому району',
    agency: 'СК',
    region: 'Ростовская область',
    headerContour: 'Следственный комитет',
    contourSub: 'Ростовская область · руководитель · СК РФ',
    dashboardTitle: 'Дашборд руководителя',
    dashboardMode: 'investigator',
    defaultView: 'dashboard',
    isManager: true,
    caseScope: { agency: 'СК', region: 'Ростовская область' }
  }),
  INV_SK_ROSTOV: enrichPersona({
    id: 'INV_SK_ROSTOV',
    roleType: 'inv',
    group: 'СК РФ',
    avatar: 'БО',
    name: 'Белова О.С.',
    role: 'Следователь · СУ',
    department: 'СУ по Ленинскому району',
    agency: 'СК',
    region: 'Ростовская область',
    headerContour: 'Следственный комитет',
    contourSub: 'Ростовская область · СУ · СК РФ',
    dashboardTitle: 'Дашборд следователя СК',
    dashboardMode: 'investigator',
    defaultView: 'cases',
    caseScope: { agency: 'СК', region: 'Ростовская область' }
  }),
  INV_LEAD_FSB: enrichPersona({
    id: 'INV_LEAD_FSB',
    roleType: 'inv_lead',
    group: 'ФСБ России',
    avatar: 'РВ',
    name: 'Родионов В.Г.',
    role: 'Руководитель следственного отдела',
    department: 'УФСБ по Краснодарскому краю',
    agency: 'ФСБ',
    region: 'Краснодарский край',
    headerContour: 'Оперативный контур',
    contourSub: 'Краснодарский край · УФСБ · ФСБ',
    dashboardTitle: 'Дашборд руководителя ФСБ',
    dashboardMode: 'investigator',
    accessDeny: ['horizon'],
    defaultView: 'dashboard',
    isManager: true,
    caseScope: { agency: 'ФСБ', region: 'Краснодарский край' }
  }),
  INV_FSB_2: enrichPersona({
    id: 'INV_FSB_2',
    roleType: 'inv',
    group: 'ФСБ России',
    avatar: 'СМ',
    name: 'Степанов М.А.',
    role: 'Следователь · УФСБ',
    department: 'УФСБ по Краснодарскому краю',
    agency: 'ФСБ',
    region: 'Краснодарский край',
    headerContour: 'Оперативный контур',
    contourSub: 'Краснодарский край · УФСБ · ФСБ',
    dashboardTitle: 'Дашборд следователя ФСБ',
    dashboardMode: 'investigator',
    accessDeny: ['horizon'],
    defaultView: 'cases',
    caseScope: { agency: 'ФСБ', region: 'Краснодарский край' }
  }),
  INV_LEAD_RGV: enrichPersona({
    id: 'INV_LEAD_RGV',
    roleType: 'inv_lead',
    group: 'Росгвардия',
    avatar: 'ДС',
    name: 'Дубровин С.П.',
    role: 'Руководитель следственного подразделения',
    department: 'Управление Росгвардии',
    agency: 'РОСГВАРДИЯ',
    region: 'Ставропольский край',
    headerContour: 'Следственный комитет',
    contourSub: 'Ставропольский край · руководитель · Росгвардия',
    dashboardTitle: 'Дашборд руководителя',
    dashboardMode: 'investigator',
    defaultView: 'dashboard',
    isManager: true,
    caseScope: { agency: 'РОСГВАРДИЯ', region: 'Ставропольский край' }
  }),
  INV_RGV_2: enrichPersona({
    id: 'INV_RGV_2',
    roleType: 'inv',
    group: 'Росгвардия',
    avatar: 'ШГ',
    name: 'Шишкин Г.О.',
    role: 'Следователь · Росгвардия',
    department: 'Управление Росгвардии',
    agency: 'РОСГВАРДИЯ',
    region: 'Ставропольский край',
    headerContour: 'Следственный комитет',
    contourSub: 'Ставропольский край · Росгвардия',
    dashboardTitle: 'Дашборд следователя',
    dashboardMode: 'investigator',
    defaultView: 'cases',
    caseScope: { agency: 'РОСГВАРДИЯ', region: 'Ставропольский край' }
  }),
  INV_LEAD_FTS: enrichPersona({
    id: 'INV_LEAD_FTS',
    roleType: 'inv_lead',
    group: 'ФТС России',
    avatar: 'ЖА',
    name: 'Жукова А.Р.',
    role: 'Руководитель следственного отдела',
    department: 'Таможня Шереметьево',
    agency: 'ФТС',
    region: 'Москва',
    headerContour: 'Следственный комитет',
    contourSub: 'Москва · ФТС · руководитель',
    dashboardTitle: 'Дашборд руководителя',
    dashboardMode: 'investigator',
    defaultView: 'dashboard',
    isManager: true,
    caseScope: { agency: 'ФТС', region: 'Москва' }
  }),
  TECH_ADMIN: enrichPersona({
    id: 'TECH_ADMIN',
    roleType: 'admin',
    adminKind: 'tech',
    group: 'Минцифры России',
    avatar: 'ТА',
    name: 'Сидоров А.В.',
    role: 'Тех. админ · ЦОД',
    department: 'Центр обработки данных',
    agency: 'TECH',
    region: 'Федеральный',
    headerContour: 'Тех. контур',
    contourSub: 'ЦОД · инфраструктура · без доступа к делам',
    dashboardTitle: 'Тех. администрирование',
    dashboardMode: 'admin',
    defaultView: 'admin',
    caseScope: null
  }),
  FUNC_ADMIN: enrichPersona({
    id: 'FUNC_ADMIN',
    roleType: 'func_admin',
    adminKind: 'func',
    adminAgencyScope: 'МВД России',
    group: 'МВД России',
    avatar: 'КВ',
    name: 'Козлов В.А.',
    role: 'Управление ИТ · МВД России',
    department: 'Управление информационных технологий',
    agency: 'MVD',
    region: 'Федеральный',
    headerContour: 'ИТ контур',
    contourSub: 'МВД России · учётные записи и доступы',
    dashboardTitle: 'Управление ИТ ведомства',
    dashboardMode: 'func_admin',
    defaultView: 'admin',
    caseScope: null
  })
};

const demoPersonaGroups = [
  { label: 'МВД России', ids: ['INV_LEAD_MVD', 'INV_MVD', 'INV_MVD_KOVALEV', 'INV_MVD_NOVIKOV', 'INV_LEAD_MVD_WEST', 'INV_MVD_SEMYONOVA', 'INV_MVD_ROSTOV', 'OPS_LEAD_MVD', 'OPS_MVD', 'OPS_MVD_2', 'OPS_MVD_3', 'EXEC_MVD', 'FUNC_ADMIN'] },
  { label: 'СК РФ', ids: ['INV_LEAD_SK', 'INV_SK', 'INV_SK_2', 'INV_SK_3', 'INV_LEAD_SK_ROSTOV', 'INV_SK_ROSTOV'] },
  { label: 'Прокуратура РФ', ids: ['PROSEC'] },
  { label: 'Военная прокуратура', ids: ['PROSEC_MIL'] },
  { label: 'ФСБ России', ids: ['INV_LEAD_FSB', 'INV_FSB', 'INV_FSB_2'] },
  { label: 'Росгвардия', ids: ['INV_LEAD_RGV', 'INV_RGV', 'INV_RGV_2'] },
  { label: 'ФСИН России', ids: ['EXEC_FSIN'] },
  { label: 'ФТС России', ids: ['INV_LEAD_FTS', 'INV_FTS', 'EXEC_FTS'] },
  { label: 'ФССП России', ids: ['EXEC_FSSP'] },
  { label: 'ФНС России', ids: ['EXEC_FNS'] },
  { label: 'Росфинмониторинг', ids: ['EXEC_RFM'] },
  { label: 'Росреестр', ids: ['EXEC_ROSREESTR'] },
  { label: 'Суды РФ', ids: ['COURT_CLERK'] },
  { label: 'Центральный банк', ids: ['EXEC_CBR'] },
  { label: 'Аналитический центр', ids: ['ANALYST'] },
  { label: 'Минцифры России', ids: ['TECH_ADMIN'] }
];

const REQUEST_SCOPES = {
  interagency: { label: 'Межведомственный', short: 'Межвед', channel: 'СМЭВ', className: 'scope-inter' },
  intra_agency: { label: 'Внутри ведомства', short: 'Ведомство', channel: 'Внутр. шина ЕПСОК', className: 'scope-agency' },
  intra_department: { label: 'Внутри отдела', short: 'Отдел', channel: 'Локальный контур', className: 'scope-dept' }
};

const requestStatusLabels = {
  fulfilled: 'Исполнен',
  progress: 'В работе',
  submitted: 'Отправлен',
  draft: 'Черновик'
};

const platformRequests = [
  { id: 'Запрос-88421', scope: 'interagency', type: 'Движение средств', target: 'Росфинмониторинг', from: 'МВД · СО №3 · Краснодар', agency: 'Росфинмониторинг', status: 'fulfilled', sent: '02.02.2028', sla: '1,2 дня ✓' },
  { id: 'Запрос-88422', scope: 'interagency', type: 'Выписка ЕГРЮЛ', target: 'ФНС', from: 'СК · Москва', agency: 'ФНС', status: 'fulfilled', sent: '03.02.2028', sla: '0,8 дня ✓' },
  { id: 'Запрос-88450', scope: 'intra_agency', type: 'Проверка по ГИАЦ', target: 'ГИАЦ · Краснодарский край', from: 'СО №3 по Центральному району', agency: 'МВД', status: 'progress', sent: '14.06.2028', sla: 'ост. 4 ч' },
  { id: 'Запрос-88451', scope: 'intra_agency', type: 'Назначение экспертизы', target: 'ЦЭК МВД · ЮФО', from: 'СО №3 · Краснодар', agency: 'МВД', status: 'submitted', sent: '13.06.2028', sla: '3 дня' },
  { id: 'Запрос-88452', scope: 'intra_agency', type: 'Смежное СО', target: 'СО №1 · Прикубанский район', from: 'СО №3 · Краснодар', agency: 'МВД', status: 'progress', sent: '12.06.2028', sla: '1 день' },
  { id: 'Запрос-88460', scope: 'intra_department', type: 'Оперативная справка', target: 'ОУР №4 (прикреплён)', from: 'СО №3 · следователь', agency: 'МВД', department: 'СО №3 по Центральному району', status: 'fulfilled', sent: '11.06.2028', sla: '2 ч ✓' },
  { id: 'Запрос-88461', scope: 'intra_department', type: 'Согласование следственного действия', target: 'Руководитель СО №3', from: 'СО №3 · следователь', agency: 'МВД', department: 'СО №3 по Центральному району', status: 'progress', sent: '14.06.2028', sla: 'ост. 1 ч' },
  { id: 'Запрос-88462', scope: 'intra_department', type: 'Передача материалов', target: 'Опергруппа СО №3', from: 'СО №3 · следователь', agency: 'МВД', department: 'СО №3 по Центральному району', status: 'submitted', sent: '13.06.2028', sla: '4 ч' },
  { id: 'Запрос-88501', scope: 'interagency', type: 'Проверка по базам', target: 'МВД (ГИАЦ)', from: 'МВД · Краснодар', agency: 'МВД (ГИАЦ)', status: 'progress', sent: '14.06.2028', sla: 'ост. 2 ч' },
  { id: 'Запрос-88502', scope: 'interagency', type: 'Смежное дело', target: 'СК РФ', from: 'МВД · Ростов', agency: 'СК РФ', status: 'submitted', sent: '14.06.2028', sla: '1 день' },
  { id: 'Запрос-88503', scope: 'interagency', type: 'УДО / ФСИН', target: 'ФСИН', from: 'СК · Ростов', agency: 'ФСИН', status: 'draft', sent: '—', sla: '196-ФЗ' },
  { id: 'Запрос-88504', scope: 'interagency', type: 'Разрешение на оружие', target: 'Росгвардия', from: 'МВД · Ставрополь', agency: 'Росгвардия', status: 'progress', sent: '13.06.2028', sla: '150-ФЗ' },
  { id: 'Запрос-88505', scope: 'interagency', type: 'Исполнительный лист', target: 'ФССП', from: 'СК · Краснодар', agency: 'ФССП', status: 'progress', sent: '14.06.2028', sla: '229-ФЗ' },
  { id: 'Запрос-88506', scope: 'interagency', type: 'Выписка ЕГРН', target: 'Росреестр', from: 'МВД · Москва', agency: 'Росреестр', status: 'submitted', sent: '13.06.2028', sla: '2 дня' },
  { id: 'Запрос-88507', scope: 'intra_agency', type: 'Судебная экспертиза', target: 'Экспертное управление СК', from: 'СУ по ЮВАО', agency: 'СК', status: 'progress', sent: '14.06.2028', sla: '5 дней' },
  { id: 'Запрос-88508', scope: 'intra_agency', type: 'Запрос в управление ОРД', target: 'Управление контрразведки УФСБ', from: 'Следственный отдел УФСБ', agency: 'ФСБ', status: 'submitted', sent: '12.06.2028', sla: '40-ФЗ' },
  { id: 'Запрос-88509', scope: 'intra_department', type: 'Согласование выезда', target: 'Руководитель УФСБ', from: 'Следователь УФСБ', agency: 'ФСБ', department: 'УФСБ по Краснодарскому краю', status: 'fulfilled', sent: '10.06.2028', sla: '1 ч ✓' },
  { id: 'Запрос-88510', scope: 'interagency', type: 'Таможенная декларация', target: 'ФТС', from: 'ФТС · Москва', agency: 'ФТС', status: 'fulfilled', sent: '10.06.2028', sla: '1,5 дня ✓' },
  { id: 'Запрос-88511', scope: 'intra_agency', type: 'Смежное таможенное СО', target: 'Таможня Домодедово', from: 'Таможня Шереметьево', agency: 'ФТС', status: 'progress', sent: '13.06.2028', sla: '1 день' },
  { id: 'Запрос-88512', scope: 'interagency', type: 'Запрос по операциям', target: 'ЦБ', from: 'МВД · Краснодар', agency: 'ЦБ', status: 'progress', sent: '14.06.2028', sla: 'ост. 1 день' }
];

const executorRequests = platformRequests;

const osintTargetTypeLabels = {
  EMAILADDR: 'Почта',
  PHONE_NUMBER: 'Телефон',
  USERNAME: 'Никнейм',
  HUMAN_NAME: 'ФИО',
  INTERNET_NAME: 'Домен / сайт',
  IP_ADDRESS: 'IP-адрес',
  INN_OGRN: 'ИНН / ОГРН',
  VEHICLE_PLATE: 'Госномер',
  CRYPTO_WALLET: 'Криптокошелёк',
  SOCIAL_ID: 'ID соцсети'
};

const osintProfileLabels = {
  passive_ru: 'Пассивный сбор',
  footprint_ru: 'Расширенный сбор',
  investigate_ru: 'Углублённый анализ',
  gov_registry_ru: 'Гос. реестры',
  gov_federal_ru: 'Федеральный контур'
};

const OSINT_PROFILES = {
  passive_ru: {
    label: 'Пассивный сбор — WHOIS, DNS, извлечение из контента',
    tiers: ['investigator', 'operative', 'supervisory'],
    depth: 1,
    modules: ['sfp_dnsresolve', 'sfp_whois', 'sfp_email', 'sfp_phone', 'sfp_pageinfo']
  },
  footprint_ru: {
    label: 'Расширенный сбор — обход сайтов, аккаунты, профили',
    tiers: ['investigator', 'operative', 'supervisory'],
    depth: 2,
    modules: ['sfp_spider', 'sfp_accounts', 'sfp_gravatar', 'sfp_social', 'sfp_webanalyze']
  },
  investigate_ru: {
    label: 'Углублённый анализ — полный whitelist модулей',
    tiers: ['investigator', 'operative'],
    depth: 3,
    modules: ['sfp_spider', 'sfp_accounts', 'sfp_names', 'sfp_keybase', 'sfp_filemeta', 'sfp_sslcert']
  },
  gov_registry_ru: {
    label: 'Гос. реестры — ЕГРЮЛ/ЕГРИП, ФССП, публичные ведомственные базы',
    tiers: ['investigator', 'operative'],
    depth: 3,
    modules: ['sfp_company', 'sfp_whois', 'sfp_webanalytics', 'gov_egrul', 'gov_fssp_public']
  },
  gov_federal_ru: {
    label: 'Федеральный контур — перекрёстный сбор, SMEV-подсказки, архивы',
    tiers: ['investigator'],
    depth: 4,
    modules: ['sfp_spider', 'sfp_accounts', 'gov_smev_hint', 'gov_archive', 'gov_leak_index']
  }
};

const osintModuleLabels = {
  sfp_email: 'Почтовые записи',
  sfp_phone: 'Телефонные данные',
  sfp_gravatar: 'Публичные профили',
  sfp_accounts: 'Учётные записи в сети',
  sfp_names: 'Идентификация по имени',
  sfp_spider: 'Обход веб-ресурсов',
  sfp_whois: 'Регистрационные данные',
  sfp_social: 'Социальные сети',
  sfp_keybase: 'Криптографические профили',
  sfp_dnsresolve: 'DNS-разрешение',
  sfp_webanalyze: 'Анализ веб-сайтов',
  sfp_pageinfo: 'Метаданные страниц',
  sfp_filemeta: 'EXIF / метаданные файлов',
  sfp_sslcert: 'SSL-сертификаты',
  sfp_company: 'Юридические лица',
  sfp_webanalytics: 'Веб-аналитика',
  gov_egrul: 'ЕГРЮЛ / ЕГРИП (открытый контур)',
  gov_fssp_public: 'ФССП · публичные данные',
  gov_smev_hint: 'SMEV · подсказки пересечений',
  gov_archive: 'Web Archive / кэш',
  gov_leak_index: 'Индекс утечек (изолир. контур)',
  gov_gibdd_public: 'ГИБДД · открытый контур',
  sfp_blockchain: 'Блокчейн-анализ'
};

const osintSourceTierLabels = {
  open: 'Открытый',
  semi: 'Полуоткрытый',
  gov: 'Гос. реестр',
  smev: 'SMEV-подсказка'
};

function osintModuleLabel(id) {
  return osintModuleLabels[id] || id;
}

const adminStatusLabels = {
  healthy: 'Исправен',
  degraded: 'Снижен',
  pending: 'Ожидает',
  online: 'В сети',
  cert_expiring: 'Срок серт.',
  pending_approval: 'На согласовании',
  approved: 'Одобрено',
  scheduled: 'Запланирован',
  completed: 'Завершён',
  create: 'Создание',
  assign_roles: 'Назначение ролей',
  disable: 'Отключение'
};

const serviceNames = {
  'case-management': 'Управление делами',
  'link-intelligence': 'Анализ связей',
  'interagency-hub': 'Межведомственный хаб',
  'osint-orchestrator': 'Сервис управления сбором открытых источников',
  'horizon-orchestrator': 'Сервис управления «Горизонт»',
  'audit-worm': 'Журнал аудита'
};

function formatScanId(id) {
  return id.replace(/^OSINT-/, 'Пров-');
}

function adminStatusLabel(status) {
  return adminStatusLabels[status] || status;
}

let activePersonaId = 'INV_MVD';
let currentUser = null;

function getActivePersona() {
  return demoPersonas[activePersonaId] || demoPersonas.INV_MVD;
}

async function getStoredSession() {
  const raw = sessionStorage.getItem(AUTH_STORAGE_KEY) || localStorage.getItem(AUTH_REMEMBER_KEY);
  if (!raw) return null;
  if (typeof EpsokSecurity !== 'undefined') {
    return EpsokSecurity.openSealedSession(raw);
  }
  return null;
}

async function saveSession(username, remember, personaId = activePersonaId, personaExplicit = false) {
  const inner = { personaId, at: Date.now() };
  if (personaExplicit) inner.personaExplicit = true;
  if (typeof EpsokSecurity === 'undefined') return;
  const sealed = await EpsokSecurity.sealSession(username, inner, remember);
  sessionStorage.setItem(AUTH_STORAGE_KEY, sealed);
  if (remember) localStorage.setItem(AUTH_REMEMBER_KEY, sealed);
  else localStorage.removeItem(AUTH_REMEMBER_KEY);
}

function clearSession() {
  sessionStorage.removeItem(AUTH_STORAGE_KEY);
  sessionStorage.removeItem(ACTIVE_VIEW_KEY);
  localStorage.removeItem(AUTH_REMEMBER_KEY);
  EpsokSecurity?.purgeLegacySessions?.();
  EpsokSecurity?.clearSecurityState?.();
  corpMailReady = false;
  corpMailThreads = [];
}

function saveActiveView(viewId) {
  if (!viewId) return;
  try {
    sessionStorage.setItem(ACTIVE_VIEW_KEY, viewId);
  } catch { /* ignore quota */ }
}

function getSavedActiveView() {
  try {
    return sessionStorage.getItem(ACTIVE_VIEW_KEY);
  } catch {
    return null;
  }
}

function clearSavedActiveView() {
  sessionStorage.removeItem(ACTIVE_VIEW_KEY);
}

function isViewAllowedForPersona(viewId, p = getActivePersona()) {
  if (!viewId) return false;
  if (utilViews.includes(viewId)) return true;
  return p.allowedViews.includes(viewId);
}

function resolveInitialView(p = getActivePersona()) {
  const saved = getSavedActiveView();
  if (saved && isViewAllowedForPersona(saved, p)) return saved;
  return 'dashboard';
}

async function isAuthenticated() {
  const session = await getStoredSession();
  if (!session?.username) return false;
  const user = authUsers[session.username];
  if (!user) {
    clearSession();
    return false;
  }
  currentUser = { username: session.username, ...user };
  const defaultPersonaId = user.personaId || 'INV_MVD';
  const remember = !!localStorage.getItem(AUTH_REMEMBER_KEY);
  if (session.personaId && demoPersonas[session.personaId]) {
    if (!session.personaExplicit && session.personaId === 'INV_MVD' && defaultPersonaId !== 'INV_MVD') {
      activePersonaId = defaultPersonaId;
      await saveSession(session.username, remember, activePersonaId);
    } else {
      activePersonaId = session.personaId;
    }
  } else {
    activePersonaId = defaultPersonaId;
    await saveSession(session.username, remember, activePersonaId);
  }
  return true;
}

function syncAuthShellVisibility(loggedIn) {
  document.documentElement.dataset.auth = loggedIn ? 'app' : 'login';
}

function showLoginScreen() {
  syncAuthShellVisibility(false);
  document.getElementById('login-screen')?.classList.remove('hidden');
  document.getElementById('app-root')?.classList.add('hidden');
  document.getElementById('login-error')?.classList.add('hidden');
}

function hideLoginScreen() {
  syncAuthShellVisibility(true);
  document.getElementById('login-screen')?.classList.add('hidden');
  document.getElementById('app-root')?.classList.remove('hidden');
}

function fillDemoLogin(username) {
  const userInput = document.getElementById('login-user');
  const passInput = document.getElementById('login-pass');
  if (userInput) userInput.value = username;
  if (passInput) passInput.value = 'epsok2028';
  document.getElementById('login-error')?.classList.add('hidden');
}

async function loginDemoUser(username) {
  const errEl = document.getElementById('login-error');
  try {
    fillDemoLogin(username);
    await submitLogin({ preventDefault() {} });
  } catch (err) {
    console.error(err);
    if (errEl) {
      errEl.textContent = 'Ошибка входа. Обновите страницу (Ctrl+F5) и попробуйте снова.';
      errEl.classList.remove('hidden');
    }
  }
}

async function submitLogin(e) {
  e.preventDefault();
  const username = document.getElementById('login-user').value.trim().toLowerCase();
  const password = document.getElementById('login-pass').value;
  const remember = document.getElementById('login-remember')?.checked;
  const errEl = document.getElementById('login-error');
  const btn = document.getElementById('login-submit-btn');
  const user = authUsers[username];

  if (btn) btn.disabled = true;
  try {
    const auth = await EpsokSecurity.verifyPassword(password);
    if (auth.locked && errEl) {
      errEl.textContent = auth.message;
      errEl.classList.remove('hidden');
      return;
    }
    if (!user || !auth.ok) {
      if (errEl) {
        errEl.textContent = 'Неверный логин или пароль. Для демо: ivanov.sp / epsok2028';
        errEl.classList.remove('hidden');
      }
      return;
    }

    activePersonaId = user.personaId || 'INV_MVD';
    await saveSession(username, remember, activePersonaId);
    currentUser = { username, ...user };
    hideLoginScreen();
    applyDemoPersona();
    initSidebar();
    updateSecurityStrip();
    await loadHrState();
    await loadEvidencePackages();
    bootstrapAllCaseGraphs();
    try {
      await ensureCorpMailReady();
    } catch (mailErr) {
      console.error(mailErr);
      await resetCorpMailState();
      showToast('Почтовый ящик восстановлен из демо-шаблона');
    }
    updateMailSidebarBadge();
    clearSavedActiveView();
    showView('dashboard');
    showToast(`Добро пожаловать, ${user.displayName}`);
  } catch (err) {
    console.error(err);
    if (errEl) {
      errEl.textContent = 'Ошибка входа. Обновите страницу (Ctrl+F5) или очистите данные сайта.';
      errEl.classList.remove('hidden');
    }
  } finally {
    if (btn) btn.disabled = false;
  }
}

function logout() {
  clearSession();
  currentUser = null;
  activePersonaId = 'INV_MVD';
  graphView.deactivate();
  document.getElementById('login-form')?.reset();
  document.getElementById('login-remember').checked = false;
  showLoginScreen();
}

function showUtilView(viewId) {
  showView(viewId);
}

function showRegTab(tabId) {
  document.querySelectorAll('.reg-nav-item').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.reg === tabId);
  });
  document.querySelectorAll('.reg-pane').forEach(pane => {
    pane.classList.toggle('active', pane.id === `reg-pane-${tabId}`);
  });
  if (tabId === 'laws') renderLegalBase();
}

// --- Нормативная база (регламенты) ---

let regLegalCategory = 'all';
let regLegalFiltersReady = false;

const LEGAL_DOC_TYPES = {
  code: 'Кодекс',
  federal_law: 'Федеральный закон',
  sub_law: 'Закон РФ',
  nk: 'Налоговый кодекс',
  order: 'Приказ / регламент',
  pp: 'Постановление Правительства',
  international: 'Международный договор'
};

const LEGAL_AGENCY_LABELS = {
  MVD: 'МВД', SK: 'СК', PROSECUTOR: 'Прокуратура', MILPROSEC: 'Военная прокуратура',
  FSB: 'ФСБ', FNS: 'ФНС', RFM: 'Росфинмониторинг', FTS: 'ФТС', FSIN: 'ФСИН',
  RGV: 'Росгвардия', FSSP: 'ФССП', ROSREESTR: 'Росреестр', COURT: 'Суды',
  CBR: 'Банк России', MINDIG: 'Минцифры', PLATFORM: 'Платформа', ALL: 'Все контуры'
};

const LEGAL_BASE_CATEGORIES = [
  { id: 'criminal_procedure', label: 'Уголовное судопроизводство', icon: '⚖' },
  { id: 'agency_powers', label: 'Полномочия ведомств', icon: '🏛' },
  { id: 'operative', label: 'ОРД и оперативный контур', icon: '◎' },
  { id: 'supervisory', label: 'Прокурорский надзор', icon: '👁' },
  { id: 'personal_data', label: 'ПДн и информационная безопасность', icon: '🔒' },
  { id: 'interagency', label: 'Межведомственное взаимодействие', icon: '⇄' },
  { id: 'finance_tax', label: 'Налоги и финансы', icon: '₽' },
  { id: 'property_customs', label: 'Недвижимость и таможня', icon: '📦' },
  { id: 'penitentiary', label: 'УИС и содержание под стражей', icon: '⛓' },
  { id: 'enforcement', label: 'Исполнительное производство', icon: '⚡' },
  { id: 'judiciary', label: 'Судебная система и экспертизы', icon: '⚖' },
  { id: 'weapons_security', label: 'Оружие и общественная безопасность', icon: '🛡' }
];

const LEGAL_BASE = [
  { id: 'upk', code: 'УПК РФ', docType: 'code', category: 'criminal_procedure', title: 'Уголовно-процессуальный кодекс РФ', articles: 'ст. 7–21, 37–41, 75, 89, 109, 144–186, 195–207, 217, 223, 226', summary: 'Дознание, предварительное следствие, запросы сведений, сроки, доказательства, подследственность.', epsok: 'Deadline Engine · карточка дела · типы запросов · CDR (ст. 186) · экспорт пакетов', agencies: ['MVD', 'SK', 'PROSECUTOR', 'FSB', 'COURT'], tags: ['следствие', 'сроки', 'запросы'] },
  { id: 'uk', code: 'УК РФ', docType: 'code', category: 'criminal_procedure', title: 'Уголовный кодекс РФ', articles: 'ст. 137, 272, 274.1', summary: 'Ответственность за нарушение неприкосновенности частной жизни и неправомерный доступ к компьютерной информации.', epsok: 'Основание дисциплинарных и уголовных последствий при нарушении POL-005', agencies: ['ALL'], tags: ['ответственность', 'аудит'] },
  { id: 'koap', code: 'КоАП РФ', docType: 'code', category: 'criminal_procedure', title: 'Кодекс РФ об административных правонарушениях', articles: 'ст. 13.11, 13.14', summary: 'Административная ответственность за нарушения в сфере ПДн и незаконный оборот данных.', epsok: 'Санкции при массовом просмотре и экспорте без основания', agencies: ['ALL'], tags: ['ПДн', 'ответственность'] },
  { id: 'fz3', code: '3-ФЗ', docType: 'federal_law', category: 'agency_powers', title: 'О полиции', articles: 'ст. 1–38', summary: 'Функции полиции: защита прав, профилактика, раскрытие, дознание.', epsok: 'ГИАЦ · ИБД · ГИБДД · КУСП · запросы MVD_*', agencies: ['MVD'], tags: ['полиция', 'ГИАЦ', 'розыск'] },
  { id: 'fz403', code: '403-ФЗ', docType: 'federal_law', category: 'agency_powers', title: 'О Следственном комитете РФ', articles: 'ст. 1–40', summary: 'Полномочия СК в сфере уголовного судопроизводства.', epsok: 'Смежные дела · экспертизы · подследственность SK_*', agencies: ['SK'], tags: ['СК', 'следствие'] },
  { id: 'fz40', code: '40-ФЗ', docType: 'federal_law', category: 'operative', title: 'О ФСБ России', articles: 'ст. 1–24', summary: 'Полномочия в сфере обеспечения безопасности, контрразведки, борьбы с терроризмом.', epsok: 'ОРД-контур · грифованные дела · FSB_*', agencies: ['FSB'], tags: ['ФСБ', 'ОРД'] },
  { id: 'fz144', code: '144-ФЗ', docType: 'federal_law', category: 'operative', title: 'Об оперативно-розыскной деятельности', articles: 'ст. 1–18', summary: 'Правовые основы ОРД, виды оперативно-розыскных мероприятий.', epsok: 'Оперативный контур · номер ОРД · модуль «Горизонт» (огран.)', agencies: ['MVD', 'FSB'], tags: ['ОРД', 'оперативный'] },
  { id: 'fz5485', code: '5485-1', docType: 'sub_law', category: 'operative', title: 'О государственной тайне', articles: 'ст. 1–28', summary: 'Режим грифованной информации и доступ к секретным сведениям.', epsok: 'Контур В · разграничение следственного и оперативного', agencies: ['FSB', 'PLATFORM'], tags: ['гриф', 'секретность'] },
  { id: 'fz210', code: '210-ФЗ', docType: 'federal_law', category: 'interagency', title: 'Об организации деятельности МВД и ФСБ', articles: 'ч. 1–2', summary: 'Разграничение полномочий МВД и ФСБ; электронное межведомственное взаимодействие.', epsok: 'Маршрутизация СМЭВ · адаптеры ведомств', agencies: ['MVD', 'FSB', 'MINDIG'], tags: ['СМЭВ', 'разграничение'] },
  { id: 'fz2202', code: '2202-1', docType: 'sub_law', category: 'supervisory', title: 'О прокуратуре РФ', articles: 'ст. 1, 21–22, 57', summary: 'Надзор за соблюдением законов, полномочия прокурора в уголовном процессе.', epsok: 'Надзорный доступ · контроль сроков · Serendipity (POL-007)', agencies: ['PROSECUTOR', 'MILPROSEC'], tags: ['надзор', 'прокуратура'] },
  { id: 'fz152', code: '152-ФЗ', docType: 'federal_law', category: 'personal_data', title: 'О персональных данных', articles: 'ст. 6, 10, 18–19', summary: 'Обработка ПДн, уровни защищённости, права субъектов.', epsok: 'Шифрование at-rest · POL-005 · классификация ИСПДн', agencies: ['ALL', 'PLATFORM'], tags: ['ПДн', 'защита'] },
  { id: 'fz149', code: '149-ФЗ', docType: 'federal_law', category: 'personal_data', title: 'Об информации, информационных технологиях и защите информации', articles: 'ст. 2, 10, 14', summary: 'Общие требования к информационным системам и обмену данными.', epsok: 'ГИС ЕПСОК · корпоративная почта · ЕСИА', agencies: ['MINDIG', 'ALL'], tags: ['ИТ', 'информация'] },
  { id: 'fz187', code: '187-ФЗ', docType: 'federal_law', category: 'personal_data', title: 'О безопасности критической информационной инфраструктуры', articles: 'ст. 1–12', summary: 'ЕПСОК как объект КИИ, меры защиты и ГосСОПКА.', epsok: 'Категорирование ЦОД · мониторинг TECH_ADMIN', agencies: ['MINDIG', 'PLATFORM'], tags: ['КИИ', 'безопасность'] },
  { id: 'fstec17', code: 'Приказ ФСТЭК № 17', docType: 'order', category: 'personal_data', title: 'Меры защиты информации в ГИС', articles: '—', summary: 'Требования к защите информации в государственных информационных системах.', epsok: 'Архитектура безопасности · аудит конфигураций', agencies: ['PLATFORM'], tags: ['ФСТЭК', 'ГИС'] },
  { id: 'fstec21', code: 'Приказ ФСТЭК № 21', docType: 'order', category: 'personal_data', title: 'Состав и содержание мер по защите ПДн', articles: '—', summary: 'Классификация ИСПДн и набор организационных и технических мер.', epsok: 'Уровни защищённости контуров следствия и ЦОД', agencies: ['PLATFORM'], tags: ['ФСТЭК', 'ПДн'] },
  { id: 'pp_smev', code: 'ПП РФ о СМЭВ', docType: 'pp', category: 'interagency', title: 'Правила взаимодействия через СМЭВ', articles: '—', summary: 'Регламент шлюза межведомственного электронного взаимодействия.', epsok: 'Модуль «Запросы» · SLA · статусы исполнения', agencies: ['MINDIG', 'ALL'], tags: ['СМЭВ', 'межвед'] },
  { id: 'fz115', code: '115-ФЗ', docType: 'federal_law', category: 'finance_tax', title: 'О противодействии легализации доходов (ПОД/ФТ)', articles: 'ст. 7, 8', summary: 'Сбор и передача сведений о подозрительных операциях.', epsok: 'Запросы RFM_* · кластеры «Горизонт»', agencies: ['RFM', 'FNS', 'CBR'], tags: ['ПОД/ФТ', 'финансы'] },
  { id: 'fz129', code: '129-ФЗ', docType: 'federal_law', category: 'finance_tax', title: 'О государственной регистрации юридических лиц', articles: 'ст. 1–30', summary: 'ЕГРЮЛ / ЕГРИП, сведения о юридических лицах и ИП.', epsok: 'FNS_EGRUL · проверка контрагентов', agencies: ['FNS'], tags: ['ЕГРЮЛ', 'ЮЛ'] },
  { id: 'fz134', code: '134-ФЗ', docType: 'federal_law', category: 'finance_tax', title: 'О налоговых органах', articles: 'ст. 1–20', summary: 'Функции ФНС и информационное взаимодействие с правоохранительными органами.', epsok: 'Исполнение запросов ФНС · FNS_*', agencies: ['FNS'], tags: ['ФНС', 'налоги'] },
  { id: 'nk', code: 'НК РФ', docType: 'nk', category: 'finance_tax', title: 'Налоговый кодекс РФ', articles: 'ст. 93, 102', summary: 'Предоставление налоговой информации при расследовании преступлений.', epsok: '2-НДФЛ · сведения о счетах · FNS_INCOME / FNS_ACCOUNT', agencies: ['FNS'], tags: ['налоги', 'доходы'] },
  { id: 'fz173', code: '173-ФЗ', docType: 'federal_law', category: 'finance_tax', title: 'О валютном регулировании и контроле', articles: 'ст. 1–30', summary: 'Валютные операции и контроль трансграничных переводов.', epsok: 'RFM-аналитика · транзитные схемы', agencies: ['RFM'], tags: ['валюта', 'ПОД/ФТ'] },
  { id: 'fz86', code: '86-ФЗ', docType: 'federal_law', category: 'finance_tax', title: 'О Центральном банке РФ', articles: 'ст. 1–25', summary: 'Надзор за кредитными организациями, взаимодействие с РФМ.', epsok: 'CBR_VIA_RFM · блокировка счетов (фаза 3)', agencies: ['CBR', 'RFM'], tags: ['ЦБ', 'банки'] },
  { id: 'fz289', code: '289-ФЗ', docType: 'federal_law', category: 'property_customs', title: 'О таможенном регулировании', articles: 'ст. 1–50', summary: 'Таможенный контроль, декларации, перемещение товаров.', epsok: 'FTS_DECLARATION · FTS_CONSIGNOR', agencies: ['FTS'], tags: ['таможня', 'контрабанда'] },
  { id: 'tk_eaeu', code: 'ТК ЕАЭС', docType: 'international', category: 'property_customs', title: 'Таможенный кодекс ЕАЭС', articles: 'гл. 1–5', summary: 'Таможенные процедуры в рамках Евразийского экономического союза.', epsok: 'Код ТН ВЭД · маршруты поставок', agencies: ['FTS'], tags: ['ЕАЭС', 'таможня'] },
  { id: 'fz218', code: '218-ФЗ', docType: 'federal_law', category: 'property_customs', title: 'О государственной регистрации недвижимости', articles: 'ст. 1–35', summary: 'ЕГРН, права на недвижимое имущество, обременения.', epsok: 'ROSREESTR_EGRN · обременения', agencies: ['ROSREESTR'], tags: ['ЕГРН', 'недвижимость'] },
  { id: 'fz196', code: '196-ФЗ', docType: 'federal_law', category: 'penitentiary', title: 'Об уголовно-исполнительной системе', articles: 'ст. 1–30', summary: 'Исполнение наказаний, учёт осуждённых, УДО.', epsok: 'FSIN_CUSTODY · FSIN_PAROLE', agencies: ['FSIN'], tags: ['УИС', 'УДО'] },
  { id: 'fz103', code: '103-ФЗ', docType: 'federal_law', category: 'penitentiary', title: 'О содержании под стражей подозреваемых и обвиняемых', articles: 'ст. 1–20', summary: 'Содержание в СИЗО, сроки, порядок содержания.', epsok: 'FSIN-запросы · сроки содержания (ст. 109 УПК)', agencies: ['FSIN', 'COURT'], tags: ['СИЗО', 'содержание'] },
  { id: 'fz229', code: '229-ФЗ', docType: 'federal_law', category: 'enforcement', title: 'Об исполнительном производстве', articles: 'ст. 1–30', summary: 'Принудительное исполнение судебных актов, арест имущества.', epsok: 'FSSP_ENFORCE · FSSP_ARREST · запрет на выезд', agencies: ['FSSP'], tags: ['приставы', 'арест'] },
  { id: 'fz226', code: '226-ФЗ', docType: 'federal_law', category: 'weapons_security', title: 'О войсках национальной гвардии', articles: 'ст. 1–25', summary: 'Охрана общественного порядка, частная охрана, оружие.', epsok: 'RGV_WEAPON · учёт ЧОО', agencies: ['RGV'], tags: ['Росгвардия', 'охрана'] },
  { id: 'fz150', code: '150-ФЗ', docType: 'federal_law', category: 'weapons_security', title: 'Об оружии', articles: 'ст. 1–30', summary: 'Оборот гражданского и служебного оружия, разрешения.', epsok: 'Проверка разрешений · RGV_WEAPON', agencies: ['RGV', 'MVD'], tags: ['оружие'] },
  { id: 'fz114', code: '114-ФЗ', docType: 'federal_law', category: 'weapons_security', title: 'О противодействии экстремистской деятельности', articles: 'ст. 1–15', summary: 'Меры по противодействию экстремизму, совместные мероприятия.', epsok: 'Связка дел · оперативное взаимодействие', agencies: ['MVD', 'FSB', 'RGV'], tags: ['экстремизм'] },
  { id: 'fz118', code: '118-ФЗ', docType: 'federal_law', category: 'judiciary', title: 'О судебной системе РФ', articles: 'ст. 1–20', summary: 'Полномочия судов, судебная система.', epsok: 'Привязка определений · пакеты доказательств в суд', agencies: ['COURT'], tags: ['суды'] },
  { id: 'fz73', code: '73-ФЗ', docType: 'federal_law', category: 'judiciary', title: 'О государственной судебно-экспертной деятельности', articles: 'ст. 1–20', summary: 'Назначение и проведение судебных экспертиз.', epsok: 'SK_EXPERTISE · сроки экспертиз в Deadline Engine', agencies: ['SK', 'COURT'], tags: ['экспертиза'] }
];

function prepareLegalBaseFilters() {
  if (regLegalFiltersReady) return;
  const typeSel = document.getElementById('reg-laws-type');
  const agencySel = document.getElementById('reg-laws-agency');
  if (!typeSel || !agencySel) return;
  const types = [...new Set(LEGAL_BASE.map(l => l.docType))];
  typeSel.innerHTML = '<option value="">Все типы</option>' + types.map(t =>
    `<option value="${t}">${escapeHtml(LEGAL_DOC_TYPES[t] || t)}</option>`
  ).join('');
  const agencies = [...new Set(LEGAL_BASE.flatMap(l => l.agencies))].sort((a, b) =>
    (LEGAL_AGENCY_LABELS[a] || a).localeCompare(LEGAL_AGENCY_LABELS[b] || b, 'ru')
  );
  agencySel.innerHTML = '<option value="">Все ведомства</option>' + agencies.map(id =>
    `<option value="${id}">${escapeHtml(LEGAL_AGENCY_LABELS[id] || id)}</option>`
  ).join('');
  regLegalFiltersReady = true;
}

function setRegLegalCategory(catId) {
  regLegalCategory = catId;
  renderLegalBase();
}

function getFilteredLegalBase() {
  const q = (document.getElementById('reg-laws-search')?.value || '').trim().toLowerCase();
  const docType = document.getElementById('reg-laws-type')?.value || '';
  const agency = document.getElementById('reg-laws-agency')?.value || '';
  return LEGAL_BASE.filter(l => {
    if (regLegalCategory !== 'all' && l.category !== regLegalCategory) return false;
    if (docType && l.docType !== docType) return false;
    if (agency && !l.agencies.includes(agency)) return false;
    if (!q) return true;
    const catLabel = LEGAL_BASE_CATEGORIES.find(c => c.id === l.category)?.label || '';
    const hay = [
      l.code, l.title, l.articles, l.summary, l.epsok, catLabel,
      LEGAL_DOC_TYPES[l.docType],
      ...l.tags,
      ...l.agencies.map(a => LEGAL_AGENCY_LABELS[a] || a)
    ].join(' ').toLowerCase();
    return hay.includes(q);
  });
}

function renderLegalBaseCard(l) {
  const cat = LEGAL_BASE_CATEGORIES.find(c => c.id === l.category);
  return `<article class="reg-law-card">
    <div class="reg-law-head">
      <strong>${escapeHtml(l.code)}</strong>
      <span class="reg-tag">${escapeHtml(LEGAL_DOC_TYPES[l.docType] || 'Акт')}</span>
    </div>
    <p class="reg-law-title">${escapeHtml(l.title)}</p>
    <p class="reg-law-summary">${escapeHtml(l.summary)}</p>
    <span class="reg-law-art">${escapeHtml(l.articles)}</span>
    <p class="reg-law-epsok"><span class="reg-law-epsok-label">ЕПСОК:</span> ${escapeHtml(l.epsok)}</p>
    <div class="reg-law-agencies">${l.agencies.map(a =>
      `<span>${escapeHtml(LEGAL_AGENCY_LABELS[a] || a)}</span>`
    ).join('')}</div>
    ${cat ? `<span class="reg-law-cat-tag">${escapeHtml(cat.icon)} ${escapeHtml(cat.label)}</span>` : ''}
  </article>`;
}

function renderLegalBase() {
  prepareLegalBaseFilters();
  const catEl = document.getElementById('reg-laws-categories');
  const resultsEl = document.getElementById('reg-laws-results');
  const statsEl = document.getElementById('reg-laws-stats');
  const kpiEl = document.getElementById('reg-kpi-laws');
  if (!catEl || !resultsEl) return;

  const filtered = getFilteredLegalBase();
  const total = LEGAL_BASE.length;

  if (kpiEl) kpiEl.textContent = String(total);
  if (statsEl) {
    statsEl.textContent = filtered.length === total
      ? `${total} актов в ${LEGAL_BASE_CATEGORIES.length} разделах`
      : `Показано ${filtered.length} из ${total}`;
  }

  const catCounts = new Map();
  LEGAL_BASE.forEach(l => catCounts.set(l.category, (catCounts.get(l.category) || 0) + 1));
  catEl.innerHTML = `<button type="button" class="reg-laws-cat-chip${regLegalCategory === 'all' ? ' active' : ''}" onclick="setRegLegalCategory('all')">Все <span class="reg-laws-cat-count">${total}</span></button>`
    + LEGAL_BASE_CATEGORIES.map(c =>
      `<button type="button" class="reg-laws-cat-chip${regLegalCategory === c.id ? ' active' : ''}" onclick="setRegLegalCategory('${c.id}')"><span class="reg-laws-cat-icon" aria-hidden="true">${c.icon}</span>${escapeHtml(c.label)} <span class="reg-laws-cat-count">${catCounts.get(c.id) || 0}</span></button>`
    ).join('');

  if (!filtered.length) {
    resultsEl.innerHTML = `<div class="reg-laws-empty"><span class="reg-laws-empty-icon" aria-hidden="true">⌕</span><p class="muted">Ничего не найдено. Измените запрос или снимите фильтры.</p></div>`;
    return;
  }

  if (regLegalCategory !== 'all') {
    resultsEl.innerHTML = `<div class="reg-law-grid">${filtered.map(renderLegalBaseCard).join('')}</div>`;
    return;
  }

  const byCat = new Map();
  filtered.forEach(l => {
    if (!byCat.has(l.category)) byCat.set(l.category, []);
    byCat.get(l.category).push(l);
  });
  resultsEl.innerHTML = LEGAL_BASE_CATEGORIES.filter(c => byCat.has(c.id)).map(c => `
    <section class="reg-laws-group">
      <header class="reg-laws-group-head">
        <h4><span aria-hidden="true">${c.icon}</span> ${escapeHtml(c.label)}</h4>
        <span class="reg-laws-group-count">${byCat.get(c.id).length}</span>
      </header>
      <div class="reg-law-grid">${byCat.get(c.id).map(renderLegalBaseCard).join('')}</div>
    </section>`).join('');
}

function prepareRegulationsView() {
  const kpiEl = document.getElementById('reg-kpi-laws');
  if (kpiEl) kpiEl.textContent = String(LEGAL_BASE.length);
  if (document.getElementById('reg-pane-laws')?.classList.contains('active')) renderLegalBase();
}

function scrollInfo(blockId) {
  const el = document.getElementById(blockId);
  if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
  document.querySelectorAll('.info-nav-item').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.info === blockId);
  });
}

function submitSupportTicket(e) {
  e.preventDefault();
  const category = document.getElementById('support-category').value;
  const priority = document.getElementById('support-priority').value;
  const subject = document.getElementById('support-subject').value.trim();
  const ticketId = 'ОБР-' + Date.now().toString().slice(-6);
  const priorityLabel = { normal: 'обычный', high: 'высокий', critical: 'критичный' }[priority] || priority;
  document.getElementById('support-form').reset();
  showToast(`Обращение ${ticketId} принято (${priorityLabel}). Ответ направим на указанный контакт.`);
}

function toggleSidebarCollapse() {
  const sb = document.getElementById('app-sidebar');
  if (!sb) return;
  if (isMobileNavMode()) {
    toggleMobileNav();
    return;
  }
  sb.classList.toggle('sidebar-collapsed');
  const collapsed = sb.classList.contains('sidebar-collapsed');
  localStorage.setItem('epsok-sidebar-collapsed', collapsed ? '1' : '0');
  const btn = document.getElementById('sidebar-collapse-btn');
  if (btn) {
    btn.title = collapsed ? 'Развернуть' : 'Свернуть';
    btn.setAttribute('aria-label', collapsed ? 'Развернуть меню' : 'Свернуть меню');
  }
  if (document.getElementById('view-graph')?.classList.contains('active')) graphView.resize(false);
}

const mobileNavMq = window.matchMedia('(max-width: 900px)');

function isMobileNavMode() {
  return mobileNavMq.matches;
}

function toggleMobileNav() {
  const sb = document.getElementById('app-sidebar');
  const backdrop = document.getElementById('sidebar-backdrop');
  const toggle = document.getElementById('mobile-nav-toggle');
  if (!sb || !isMobileNavMode()) return;
  const open = sb.classList.toggle('sidebar-mobile-open');
  backdrop?.classList.toggle('visible', open);
  document.body.classList.toggle('nav-open', open);
  if (toggle) {
    toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
    toggle.setAttribute('aria-label', open ? 'Закрыть меню' : 'Открыть меню');
  }
  if (document.getElementById('view-graph')?.classList.contains('active')) graphView.resize(false);
}

function closeMobileNav() {
  const sb = document.getElementById('app-sidebar');
  const backdrop = document.getElementById('sidebar-backdrop');
  const toggle = document.getElementById('mobile-nav-toggle');
  sb?.classList.remove('sidebar-mobile-open');
  backdrop?.classList.remove('visible');
  document.body.classList.remove('nav-open');
  if (toggle) {
    toggle.setAttribute('aria-expanded', 'false');
    toggle.setAttribute('aria-label', 'Открыть меню');
  }
}

function applySidebarCollapsedState() {
  const sb = document.getElementById('app-sidebar');
  const btn = document.getElementById('sidebar-collapse-btn');
  if (!sb || isMobileNavMode()) return;
  const collapsed = localStorage.getItem('epsok-sidebar-collapsed') === '1';
  sb.classList.toggle('sidebar-collapsed', collapsed);
  if (btn) {
    btn.title = collapsed ? 'Развернуть' : 'Свернуть';
    btn.setAttribute('aria-label', collapsed ? 'Развернуть меню' : 'Свернуть меню');
  }
}

function syncMobileShell() {
  const sb = document.getElementById('app-sidebar');
  if (isMobileNavMode()) {
    sb?.classList.remove('sidebar-collapsed');
    closeMobileNav();
    return;
  }
  closeMobileNav();
  applySidebarCollapsedState();
}

function initSidebar() {
  applySidebarCollapsedState();
  const profileBtn = document.getElementById('user-info-btn');
  const menu = document.getElementById('user-menu-dropdown');
  if (profileBtn && !profileBtn.dataset.bound) {
    profileBtn.dataset.bound = '1';
    profileBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      toggleUserMenu();
    });
  }
  if (!document.body.dataset.userMenuBound) {
    document.body.dataset.userMenuBound = '1';
    document.addEventListener('click', (e) => {
      if (!menu?.classList.contains('hidden') && !e.target.closest('.user-info-wrap')) closeUserMenu();
    });
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        closeUserMenu();
        closeMobileNav();
      }
    });
  }
  if (!window.__epsokShellBound) {
    window.__epsokShellBound = true;
    mobileNavMq.addEventListener('change', syncMobileShell);
  }
  if (!window.__epsokTableResizeBound) {
    window.__epsokTableResizeBound = true;
    let resizeTimer;
    window.addEventListener('resize', () => {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(() => {
        syncMobileShell();
        if (document.getElementById('view-graph')?.classList.contains('active')) graphView.resize(false);
        const activeView = document.querySelector('.view.active')?.id;
        if (activeView === 'view-requests') renderRequests();
        else if (activeView === 'view-cases') renderCasesRegistry();
      }, 120);
    });
  }
  syncMobileShell();
}

function toggleUserMenu() {
  const menu = document.getElementById('user-menu-dropdown');
  const btn = document.getElementById('user-info-btn');
  if (!menu) return;
  const isHidden = menu.classList.toggle('hidden');
  if (btn) btn.setAttribute('aria-expanded', isHidden ? 'false' : 'true');
}

function closeUserMenu() {
  const menu = document.getElementById('user-menu-dropdown');
  const btn = document.getElementById('user-info-btn');
  menu?.classList.add('hidden');
  if (btn) btn.setAttribute('aria-expanded', 'false');
}

const roleProfiles = {
  INV: {
    avatar: 'ИС',
    name: 'Иванов С.П.',
    role: 'Следователь · МВД',
    headerContour: 'Следственный комитет',
    switchLabel: 'Сменить роль'
  },
  TECH_ADMIN: {
    avatar: 'ТА',
    name: 'Сидоров А.В.',
    role: 'Тех. админ · Минцифры / ЦОД',
    headerContour: 'Тех. контур',
    switchLabel: 'Сменить роль'
  }
};

function openDemoRoleModal() {
  renderDemoPersonaModal();
  document.getElementById('demo-role-modal')?.classList.remove('hidden');
}

function closeDemoRoleModal() {
  document.getElementById('demo-role-modal')?.classList.add('hidden');
}

function getPersonaHierarchyBadge(p) {
  if (p.roleType === 'admin') return { kind: 'tech_admin', label: 'Тех. админ' };
  if (p.roleType === 'func_admin') return { kind: 'func_admin', label: 'Управление ИТ' };
  if (p.isManager || p.roleType === 'inv_lead') return { kind: 'manager', label: 'Руководитель' };
  if (p.roleType === 'inv' || p.roleType === 'ops') return { kind: 'subordinate', label: 'Подчинённый' };
  if (p.roleType === 'prosecutor') return { kind: 'prosecutor', label: 'Прокуратура' };
  if (p.roleType === 'prosecutor_mil') return { kind: 'prosecutor', label: 'Военная прокуратура' };
  if (p.roleType === 'executor') return { kind: 'executor', label: 'Исполнитель' };
  if (p.roleType === 'analyst') return { kind: 'analyst', label: 'Аналитика' };
  if (p.roleType === 'court') return { kind: 'court', label: 'Суды' };
  return { kind: 'external', label: 'Смежный контур' };
}

function sortPersonaIdsForGroup(ids) {
  const rank = { manager: 0, tech_admin: 0, func_admin: 1, subordinate: 2, prosecutor: 3, executor: 4, analyst: 5, court: 6, external: 7 };
  return [...ids].sort((a, b) => {
    const pa = demoPersonas[a];
    const pb = demoPersonas[b];
    const ra = rank[getPersonaHierarchyBadge(pa).kind] ?? 9;
    const rb = rank[getPersonaHierarchyBadge(pb).kind] ?? 9;
    if (ra !== rb) return ra - rb;
    return pa.name.localeCompare(pb.name, 'ru');
  });
}

function getDemoPersonaCardLine(p) {
  if (p.region && p.region !== 'Федеральный' && p.department) {
    return `${p.region} · ${p.department}`;
  }
  return p.department || p.role || '';
}

function renderDemoPersonaModal() {
  const el = document.getElementById('demo-persona-groups');
  if (!el) return;
  el.innerHTML = demoPersonaGroups.map(g => {
    const sorted = sortPersonaIdsForGroup(g.ids);
    const cards = sorted.map(id => {
      const p = demoPersonas[id];
      const active = id === activePersonaId ? ' active' : '';
      const badge = getPersonaHierarchyBadge(p);
      return `<button type="button" class="demo-role-card ${badge.kind}${active}" onclick="selectDemoPersona('${id}')">
        <span class="demo-role-avatar">${p.avatar}</span>
        <span class="demo-role-body">
          <span class="demo-role-name">${escapeHtml(p.name)}</span>
          <span class="demo-role-line">${escapeHtml(getDemoPersonaCardLine(p))}</span>
        </span>
      </button>`;
    }).join('');
    return `<section class="demo-agency-block">
      <div class="demo-agency-head">
        <span class="demo-agency-name">${escapeHtml(g.label)}</span>
        <span class="demo-agency-count">${sorted.length}</span>
      </div>
      <div class="demo-role-list">${cards}</div>
    </section>`;
  }).join('');
}

function selectDemoPersona(personaId) {
  if (!demoPersonas[personaId]) return;
  activePersonaId = personaId;
  if (currentUser) {
    void saveSession(currentUser.username, !!localStorage.getItem(AUTH_REMEMBER_KEY), personaId, true);
  }
  closeDemoRoleModal();
  profileViewPersonaId = null;
  profileTab = 'card';
  staffTab = personaId === 'TECH_ADMIN' ? 'structures' : personaId === 'FUNC_ADMIN' ? 'accounts' : 'team';
  activeAdminModule = personaId === 'TECH_ADMIN' ? 'SVC' : personaId === 'FUNC_ADMIN' ? 'USR' : activeAdminModule;
  if (personaId === 'FUNC_ADMIN') activeStaffStructure = 'МВД России';
  applyDemoPersona();
  const p = getActivePersona();
  const currentView = document.querySelector('.view.active')?.id?.replace('view-', '');
  const targetView = p.allowedViews.includes(currentView) ? currentView : p.defaultView;
  showView(targetView);
  showToast(`Демо: ${p.name} · ${p.role}`);
}

function getAdminKind(p = getActivePersona()) {
  if (p?.adminKind) return p.adminKind;
  if (p?.id === 'TECH_ADMIN') return 'tech';
  if (p?.id === 'FUNC_ADMIN') return 'func';
  return null;
}

function isTechAdminPersona(p = getActivePersona()) {
  return getAdminKind(p) === 'tech';
}

function isFuncAdminPersona(p = getActivePersona()) {
  return getAdminKind(p) === 'func';
}

function isAnyAdminPersona(p = getActivePersona()) {
  return !!getAdminKind(p);
}

function canViewMailCryptoAdmin(p = getActivePersona()) {
  return isTechAdminPersona(p);
}

function syncMailAdminVisibility() {
  const techAdmin = canViewMailCryptoAdmin();
  document.getElementById('mail-compose-crypto-preview')?.classList.toggle('hidden', !techAdmin);
  document.querySelector('.mail-secure-pill-gost')?.classList.toggle('hidden', !techAdmin);
  document.querySelector('.mail-secure-pill-layers')?.classList.toggle('hidden', !techAdmin);
  const detail = document.getElementById('mail-secure-detail');
  if (detail) {
    detail.textContent = techAdmin
      ? '4–6 уровней AES-256-GCM + HMAC · ГОСТ Р 34.12-2015 · в хранилище и по сети — только шифротекст'
      : 'Сквозное шифрование · содержимое доступно только участникам переписки';
  }
}

function getAdminModulesForPersona(p = getActivePersona()) {
  const kind = getAdminKind(p);
  if (!kind) return [];
  return adminModules.filter(m => m.kinds?.includes(kind));
}

function ensureAdminModuleAllowed() {
  const mods = getAdminModulesForPersona();
  if (!mods.some(m => m.id === activeAdminModule)) {
    activeAdminModule = mods[0]?.id || 'SVC';
  }
}

function getStructuresAgencyGroups() {
  const p = getActivePersona();
  if (getAdminKind(p) === 'func' && p.adminAgencyScope) {
    return demoPersonaGroups.filter(g => g.label === p.adminAgencyScope);
  }
  return demoPersonaGroups;
}

function structuresUseSimpleCards() {
  return getAdminKind() === 'func';
}

function updateNavigationForPersona(p) {
  const allowed = new Set(p.allowedViews);
  const adminKind = getAdminKind(p);
  const showStaff = allowed.has('staff');

  document.querySelector('.nav-admin')?.classList.toggle('hidden', !adminKind);
  document.querySelector('.nav-staff')?.classList.toggle('hidden', !showStaff);
  document.querySelector('.nav-section-admin')?.classList.toggle('hidden', !adminKind);
  document.querySelector('.nav-section-hr')?.classList.toggle('hidden', !showStaff);
  const navAdminLabel = document.getElementById('nav-admin-label');
  if (navAdminLabel) {
    navAdminLabel.textContent = adminKind === 'func' ? 'Управление ИТ' : adminKind === 'tech' ? 'Тех. админ' : 'Тех. администрирование';
  }

  document.querySelectorAll('.nav-item[data-view]').forEach(btn => {
    const view = btn.dataset.view;
    btn.classList.toggle('hidden', !allowed.has(view));
    btn.classList.remove('nav-disabled');
  });

  document.querySelectorAll('.nav-section-label').forEach(label => {
    if (label.classList.contains('nav-section-hr') || label.classList.contains('nav-section-admin')) return;
    let el = label.nextElementSibling;
    let hasVisible = false;
    while (el && !el.classList.contains('nav-section-label')) {
      if (el.classList.contains('nav-item') && !el.classList.contains('hidden')) hasVisible = true;
      el = el.nextElementSibling;
    }
    label.classList.toggle('hidden', !hasVisible);
  });
}

function getHeaderSubtitle(currentView, p, region, c, inCaseContext) {
  if (inCaseContext && c) return `${c.id} · ${c.region}`;
  if (currentView === 'admin' || currentView === 'func_admin') {
    return p.headerContour || titles[currentView] || '—';
  }
  const pageLabel = titles[currentView];
  if (pageLabel && region && region !== '—') {
    return `${region} · ${pageLabel.charAt(0).toLowerCase()}${pageLabel.slice(1)}`;
  }
  if (pageLabel) return pageLabel;
  const tail = p.headerContour || '';
  return tail && region && region !== '—' ? `${region} · ${tail}` : (region !== '—' ? region : tail || '—');
}

function updateHeaderContext() {
  const p = getActivePersona();
  const pill = document.getElementById('contour-pill');
  const sub = document.querySelector('.header-sub');
  let dept = p.department || '—';
  let agency = p.group || '—';
  let region = p.region || '—';
  try {
    const rec = getPersonnelRecord(p.id);
    if (rec?.department) dept = rec.department;
    if (rec?.agencyName) agency = rec.agencyName;
    if (rec?.region) region = rec.region;
  } catch { /* ignore */ }
  const currentView = document.querySelector('.view.active')?.id?.replace('view-', '');
  const contourLine = `${dept} · ${agency}`;
  const caseViews = ['case', 'graph', 'deadlines', 'horizon', 'suspects', 'osint'];
  const c = getCaseById(activeCaseId);
  const inCaseContext = !!(c && personaCanAccessCase(c.id) && caseViews.includes(currentView));

  if (pill) {
    pill.textContent = contourLine;
    pill.title = `${p.headerContour || 'Контур'} · ${p.name}`;
    pill.classList.remove('hidden');
  }
  if (sub) {
    sub.classList.remove('status-pill');
    sub.textContent = getHeaderSubtitle(currentView, p, region, c, inCaseContext);
  }
}

function applyDemoPersona() {
  const p = getActivePersona();
  const nameEl = document.getElementById('user-name');
  if (nameEl) nameEl.textContent = p.name;
  const corpEmail = getCorporateEmail(p.id);
  const corpEmailEl = document.getElementById('sidebar-corp-email');
  if (corpEmailEl) corpEmailEl.textContent = corpEmail;
  updateMailSidebarBadge();
  updateHeaderContext();
  updateSecurityStrip();
  syncMailAdminVisibility();
  const platformStatus = document.getElementById('platform-status-pill');
  if (platformStatus) platformStatus.classList.toggle('hidden', !['admin', 'func_admin'].includes(p.roleType));

  updateNavigationForPersona(p);
  syncCapabilityButtons(p);

  applyPersonaCaseDefaults();
  renderDashboard();
  const currentView = document.querySelector('.view.active')?.id?.replace('view-', '');
  if (currentView === 'requests') renderRequests();
  if (currentView === 'agencies') renderAgencies();
  if (currentView === 'profile') renderProfile();
  if (currentView === 'staff') renderStaff();
  if (currentView === 'suspects') renderSuspects();
  if (currentView === 'admin') renderAdmin();
}

function getPersonaDefaultFilters() {
  const p = getActivePersona();
  const scope = p.caseScope;
  if (scope === null) return { region: '', agency: '', department: '' };
  return {
    region: scope?.region || p.region || '',
    agency: scope?.agency || p.agency || '',
    department: scope?.department || p.department || ''
  };
}

function applyPersonaCaseDefaults() {
  const scope = getActivePersona().caseScope;
  const regionSel = document.getElementById('cases-filter-region');
  const deptSel = document.getElementById('cases-filter-department');
  const agencySel = document.getElementById('cases-filter-agency');
  if (!regionSel || scope === null) return;
  const defaults = getPersonaDefaultFilters();
  if (!scope) {
    regionSel.value = defaults.region;
    if (agencySel) agencySel.value = defaults.agency;
    if (deptSel) deptSel.value = defaults.department;
    updateCasesFilterUI();
    return;
  }
  if (defaults.region) regionSel.value = defaults.region;
  if (defaults.agency && agencySel) agencySel.value = defaults.agency;
  if (defaults.department && deptSel) deptSel.value = defaults.department;
  updateCasesFilterUI();
}

function isCaseLinkedFromAccessibleCase(targetCaseId) {
  return getPersonaScopedCases().some(c =>
    (c.related || []).some(r => r.id === targetCaseId)
  );
}

function personaCanAccessCase(caseId) {
  const c = getCaseById(caseId);
  if (!c) return false;
  if (getPersonaScopedCases().some(x => x.id === caseId)) return true;
  return isCaseLinkedFromAccessibleCase(caseId);
}

function renderDashboard() {
  const p = getActivePersona();
  const modes = ['investigator', 'executor', 'prosecutor', 'analyst'];
  modes.forEach(m => {
    const el = document.getElementById(`dash-${m}`);
    if (el) el.classList.add('hidden');
  });
  const mode = p.dashboardMode || 'investigator';
  if (mode === 'admin' || mode === 'func_admin') return;

  const panel = document.getElementById(`dash-${mode}`);
  if (panel) panel.classList.remove('hidden');
  if (mode === 'investigator') {
    const kpi = document.getElementById('kpi-cases-count');
    if (kpi) kpi.textContent = String(getPersonaScopedCases().length);
  }
  if (mode === 'executor') renderExecutorDashboard(p);
  if (mode === 'prosecutor') renderProsecutorDashboard(p);
  if (mode === 'analyst') renderAnalystDashboard(p);
}

function renderKpiCard({ value, label, trend, trendType = 'neutral', variant = 'cases', icon = '◫', id, onclick }) {
  const trendClass = trendType === 'up' ? 'kpi-trend--up' : trendType === 'warn' ? 'kpi-trend--warn' : '';
  const tag = onclick ? 'button' : 'div';
  const clickAttr = onclick ? ` type="button" onclick="${onclick}"` : '';
  return `<${tag} class="kpi-card kpi-card--${variant}"${clickAttr}>
    <div class="kpi-card-head"><span class="kpi-icon" aria-hidden="true">${icon}</span></div>
    <div class="kpi-value"${id ? ` id="${id}"` : ''}>${value}</div>
    <div class="kpi-label">${escapeHtml(label)}</div>
    ${trend ? `<div class="kpi-trend ${trendClass}">${escapeHtml(trend)}</div>` : ''}
  </${tag}>`;
}

function renderExecutorDashboard(p) {
  const el = document.getElementById('dash-executor');
  if (!el) return;
  const exec = p.execAgency || '';
  const data = platformRequests.filter(r => {
    if (r.scope === 'interagency') {
      return r.agency === exec || r.target === exec
        || (exec && (r.agency?.includes(exec.split(' ')[0]) || r.target?.includes(exec.split(' ')[0])));
    }
    if (r.scope === 'intra_agency') {
      return exec && (r.target.includes(exec) || (exec.includes('ГИАЦ') && r.type.includes('ГИАЦ')));
    }
    return false;
  }).slice(0, 5);
  const queue = data.length ? data : platformRequests.filter(r => r.scope === 'interagency').slice(0, 3);
  el.innerHTML = `
    <div class="panel">
      <div class="panel-header"><h2>Входящие запросы · ${escapeHtml(p.execAgency || p.group)}</h2>
        <button type="button" class="btn-sm" onclick="showView('requests')">Все запросы</button>
      </div>
      <div class="table-scroll">
        <table class="data-table">
          <thead><tr><th>ID</th><th>Уровень</th><th>Тип</th><th>От кого</th><th>Статус</th><th>SLA</th></tr></thead>
          <tbody>${data.map(r => `
            <tr><td>${r.id}</td><td>${renderRequestScopeBadge(r.scope)}</td><td>${escapeHtml(r.type)}</td><td>${escapeHtml(r.from)}</td>
            <td><span class="status ${r.status}">${requestStatusLabels[r.status] || r.status}</span></td>
            <td>${r.sla}</td></tr>`).join('')}
          </tbody>
        </table>
      </div>
    </div>`;
}

function renderProsecutorDashboard(p) {
  const el = document.getElementById('dash-prosecutor');
  if (!el) return;
  const cases = getPersonaScopedCases().filter(c => c.daysLeft != null && c.daysLeft <= 7);
  el.innerHTML = `
    <div class="kpi-grid" style="margin-bottom:1.25rem">
      ${renderKpiCard({ value: cases.length, label: 'Дела с риском срока', trend: 'контроль УПК', trendType: 'warn', variant: 'deadlines', icon: '⏱', onclick: "showView('deadlines')" })}
      ${renderKpiCard({ value: getPersonaScopedCases().length, label: 'Дел в надзоре', trend: escapeHtml(p.region), variant: 'cases', icon: '◫', onclick: "showView('cases')" })}
    </div>
    <div class="panel">
      <h2>Контроль сроков · ${escapeHtml(p.region)}</h2>
      <div class="table-scroll"><table class="data-table"><thead><tr><th>Дело</th><th>Статья</th><th>Осталось</th></tr></thead><tbody>
        ${cases.map(c => `<tr class="${c.daysLeft <= 3 ? 'row-danger' : 'row-warning'}">
          <td><button type="button" class="case-link" onclick="openCase('${c.id}')">${c.id}</button></td>
          <td>${c.article.replace(' УК РФ', '')}</td><td>${c.daysLeft} дн.</td></tr>`).join('') || '<tr><td colspan="3" class="muted">Нет критических сроков</td></tr>'}
      </tbody></table></div>
      <button type="button" class="btn-sm" style="margin-top:1rem" onclick="showView('deadlines')">Все сроки УПК</button>
    </div>`;
}

function renderAnalystDashboard(p) {
  const el = document.getElementById('dash-analyst');
  if (!el) return;
  el.innerHTML = `
    <div class="kpi-grid" style="margin-bottom:1.25rem">
      ${renderKpiCard({ value: 3, label: 'Сигналы «Горизонт»', trend: 'МВ-2847', trendType: 'up', variant: 'horizon', icon: '◈', onclick: "showView('horizon')" })}
      ${renderKpiCard({ value: 47, label: 'Дел в кластере МВ-2847', trend: '5 регионов', variant: 'cases', icon: '◫', onclick: "showView('graph')" })}
      ${renderKpiCard({ value: 23, label: 'Связи (обезлич.)', trend: '+340% к 2026 г.', trendType: 'up', variant: 'links', icon: '◎', onclick: "showView('graph')" })}
    </div>
    <div class="grid-2">
      <div class="panel"><h2>Федеральные кластеры</h2>
        <div class="cluster-list">
          <div class="cluster-item"><span class="cluster-tag fraud">Мошенничество</span><span>МВ-2847 · 5 регионов</span>
            <button class="btn-sm" onclick="showView('graph')">Граф</button></div>
          <div class="cluster-item"><span class="cluster-tag drugs">Наркотики</span><span>МВ-1923 · 3 региона</span>
            <button class="btn-sm" onclick="showView('horizon')">Горизонт</button></div>
        </div>
      </div>
      <div class="panel"><h2>Доступные модули</h2>
        <ul class="info-list" style="margin-left:1rem">
          <li>Граф связей — обезличенные узлы</li>
          <li>«Горизонт» — федеральные совпадения</li>
          <li>Реестр дел — без персональных данных</li>
        </ul>
      </div>
    </div>`;
}

function toggleDemoRole() {
  openDemoRoleModal();
}

function applyDemoRole() {
  applyDemoPersona();
}

document.querySelectorAll('.nav-item').forEach(btn => {
  btn.addEventListener('click', () => showView(btn.dataset.view));
});

function showView(viewId, options) {
  closeMobileNav();
  const isUtil = utilViews.includes(viewId);
  const p = getActivePersona();
  if (!isUtil && !p.allowedViews.includes(viewId)) {
    const msg = isTechAdminPersona(p)
      ? 'ПОЛ-008: тех. админ не имеет доступа к следственным модулям.'
      : isFuncAdminPersona(p)
        ? 'ПОЛ-008: управление ИТ не имеет доступа к содержимому дел.'
        : `Нет доступа для роли: ${p.role}`;
    showToast(msg);
    return;
  }
  document.querySelectorAll('.nav-item').forEach(b => {
    b.classList.toggle('active', !isUtil && b.dataset.view === viewId);
  });
  document.querySelectorAll('.sidebar-util-links a').forEach(a => {
    a.classList.toggle('active', isUtil && a.dataset.view === viewId);
  });
  document.querySelectorAll('.view').forEach(v => {
    v.classList.toggle('active', v.id === `view-${viewId}`);
  });
  const pageTitle = viewId === 'dashboard' && p.dashboardTitle
    ? p.dashboardTitle
    : viewId === 'admin' && isFuncAdminPersona(p)
      ? titles.func_admin
      : (titles[viewId] || viewId);
  document.getElementById('page-title').textContent = pageTitle;
  if (viewId === 'graph') {
    if (!options?.keepGraphCase) activeGraphCaseId = null;
    renderGraphView();
  } else {
    graphView.deactivate();
  }
  if (viewId === 'dashboard') renderDashboard();
  if (viewId === 'cases') {
    applyPersonaCaseDefaults();
    renderCasesRegistry();
  }
  if (viewId === 'case') renderCaseDetail(activeCaseId);
  if (viewId === 'deadlines') renderDeadlines();
  if (viewId === 'osint') { renderOsintPage(); renderOsintScans(); ensureOsintScanSelected(); renderEvidencePackages(); }
  if (viewId === 'horizon') renderHorizon();
  if (viewId === 'admin') renderAdmin();
  if (viewId === 'agencies') renderAgencies();
  if (viewId === 'requests') renderRequests();
  if (viewId === 'profile') renderProfile();
  if (viewId === 'staff') renderStaff();
  if (viewId === 'suspects') { prepareSuspectsView(); renderSuspects(); }
  if (viewId === 'mail') {
    void renderCorpMail().catch(err => {
      console.error(err);
      showToast('Не удалось загрузить почту. Попробуйте обновить страницу.');
    });
  }
  if (viewId === 'regulations') prepareRegulationsView();
  syncCapabilityButtons(p);
  updateHeaderContext();
  if (!options?.skipSave) saveActiveView(viewId);
}

function showToast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 3500);
}

const TABLE_PAGE_SIZE = 10;
const tablePages = {};
const tablePageRefresh = {};

function getTablePage(key) {
  return tablePages[key] || 1;
}

function setTablePage(key, page) {
  tablePages[key] = Math.max(1, page);
  if (key === 'structures') expandedStructurePersona = null;
  tablePageRefresh[key]?.();
}

function resetTablePage(key) {
  tablePages[key] = 1;
}

function measureTablePageSize(scrollEl, opts = {}) {
  const {
    rowHeight = 44,
    minRows = 10,
    maxRows = 40,
    reservedBottom = 72
  } = opts;
  if (!scrollEl) return TABLE_PAGE_SIZE;
  const thead = scrollEl.querySelector('thead');
  const headerH = thead?.getBoundingClientRect().height || 42;
  const top = scrollEl.getBoundingClientRect().top;
  const available = window.innerHeight - top - reservedBottom;
  const rows = Math.floor((available - headerH) / rowHeight);
  return Math.max(minRows, Math.min(maxRows, rows));
}

function paginateList(items, key, pageSize = TABLE_PAGE_SIZE) {
  const total = items.length;
  const pages = Math.max(1, Math.ceil(total / pageSize));
  let page = getTablePage(key);
  if (page > pages) {
    page = pages;
    tablePages[key] = page;
  }
  const start = (page - 1) * pageSize;
  return {
    slice: items.slice(start, start + pageSize),
    page,
    pages,
    total,
    pageSize,
    from: total ? start + 1 : 0,
    to: Math.min(start + pageSize, total),
    key
  };
}

function renderTablePagination(meta) {
  if (!meta || meta.total <= meta.pageSize) return '';
  const { key, page, pages, from, to, total } = meta;
  return `<nav class="table-pagination" aria-label="Страницы таблицы">
    <span class="table-pagination-info">${from}–${to} из ${total}</span>
    <div class="table-pagination-controls">
      <button type="button" class="btn-sm table-page-btn" ${page <= 1 ? 'disabled' : ''} onclick="setTablePage('${key}', ${page - 1})" aria-label="Предыдущая страница">←</button>
      <span class="table-pagination-pages">${page} / ${pages}</span>
      <button type="button" class="btn-sm table-page-btn" ${page >= pages ? 'disabled' : ''} onclick="setTablePage('${key}', ${page + 1})" aria-label="Следующая страница">→</button>
    </div>
  </nav>`;
}

function mountTablePagination(containerId, meta) {
  const el = document.getElementById(containerId);
  if (el) el.innerHTML = renderTablePagination(meta);
}

function simulateRequest() {
  openNewRequestModal();
}

// --- Корпоративная почта (сквозное шифрование, внутри платформы) ---

const MAIL_STORAGE_KEY = 'epsok-corp-mail-v2';
const MAIL_CRYPTO_VERSION = 2;
const MAIL_PLATFORM_KEY_SEED = 'epsok:mail:hsm:platform-keystore-v2';

const MAIL_CRYPTO_LAYERS = [
  { id: 'L1', name: 'Сквозное E2E', algo: 'AES-256-GCM · ключ получателя (ЕСИА)', scope: 'контент' },
  { id: 'L2', name: 'Согласование VKO', algo: 'AES-256-GCM · ГОСТ Р 34.10-2012 (демо)', scope: 'отправитель ↔ получатель' },
  { id: 'L2+', name: 'Контур ведомства', algo: 'AES-256-GCM · KEK региона/ведомства', scope: 'служебное / ДСП' },
  { id: 'L3', name: 'Хранение HSM', algo: 'AES-256-GCM · платформенный HSM ЦОД', scope: 'at-rest' },
  { id: 'L4', name: 'Целостность', algo: 'HMAC-SHA-256 · ГОСТ Р 34.11-2012 (Streebog, демо)', scope: 'аудит' }
];

const MAIL_CLASSIFICATION = {
  standard: { label: 'Стандарт', layers: 4, extras: [], badge: 'mail-class-standard' },
  official: { label: 'Служебное', layers: 5, extras: ['regional'], badge: 'mail-class-official' },
  restricted: { label: 'ДСП', layers: 6, extras: ['agency', 'regional'], badge: 'mail-class-restricted' }
};

let mailFolder = 'inbox';
let activeMailThreadId = null;
let corpMailThreads = [];
let corpMailReady = false;

const corpMailSystemContacts = [
  { email: 'support@epsok.gov.ru', name: 'Поддержка ЦОД', agency: 'ЕПСОК', certFp: 'S1:P0…7A2F' },
  { email: 'integration@epsok.gov.ru', name: 'Интеграции СМЭВ', agency: 'ЕПСОК', certFp: 'I4:N7…3B8C' },
  { email: 'security@epsok.gov.ru', name: 'ИБ ЕПСОК', agency: 'ЕПСОК', certFp: 'E9:K2…1D4E' }
];

const corpMailSeedPlain = [
  {
    id: 'thr-001',
    subject: 'Согласование запроса в ГИАЦ',
    messages: [
      {
        id: 'msg-001',
        from: 'morozova.ea@epsok.gov.ru',
        fromName: 'Морозова Е.А.',
        to: ['ivanov.sp@epsok.gov.ru'],
        at: '14.06.2028 09:12',
        subject: 'Согласование запроса в ГИАЦ',
        plain: 'Иванов С.П., прошу согласовать запрос в ГИАЦ по делу ЕПСОК-2028-004521. Основание — постановление №142. Срок ответа до 16.06.',
        classification: 'official',
        keyId: 'ESIA-28471',
        certFp: 'A7:F2…9C1D',
        read: false
      },
      {
        id: 'msg-002',
        from: 'ivanov.sp@epsok.gov.ru',
        fromName: 'Иванов С.П.',
        to: ['morozova.ea@epsok.gov.ru'],
        at: '14.06.2028 10:05',
        subject: 'Re: Согласование запроса в ГИАЦ',
        plain: 'Согласовано. Запрос-88512 направлен в ГИАЦ. Копия в модуле «Запросы».',
        classification: 'official',
        keyId: 'ESIA-19284',
        certFp: 'B3:E1…4F8A',
        read: true
      }
    ]
  },
  {
    id: 'thr-002',
    subject: 'ПОЛ-006: регламент проверки открытых источников',
    messages: [
      {
        id: 'msg-003',
        from: 'sidorov.av@epsok.gov.ru',
        fromName: 'Сидоров А.В.',
        to: ['ivanov.sp@epsok.gov.ru'],
        at: '13.06.2028 16:40',
        subject: 'ПОЛ-006: регламент проверки открытых источников',
        plain: 'Напоминание: перед запуском проверки открытых источников указывайте правовое основание. Все действия фиксируются в журнале аудита.',
        classification: 'standard',
        keyId: 'ESIA-31002',
        certFp: 'C8:D4…2E7B',
        read: false
      }
    ]
  },
  {
    id: 'thr-003',
    subject: 'Ротация сертификата адаптера ФТС',
    messages: [
      {
        id: 'msg-004',
        from: 'integration@epsok.gov.ru',
        fromName: 'Интеграции СМЭВ',
        to: ['sidorov.av@epsok.gov.ru'],
        at: '13.06.2028 09:08',
        subject: 'Ротация сертификата адаптера ФТС',
        plain: 'Запланирована ротация сертификата адаптера ФТС 15.06.2028 02:00. Окно обслуживания создано в консоли ЦОД.',
        classification: 'standard',
        keyId: 'SYS-INT-01',
        certFp: 'I4:N7…3B8C',
        read: true
      }
    ]
  }
];

function mailUint8ToB64(u8) {
  const bin = u8.reduce((s, b) => s + String.fromCharCode(b), '');
  return btoa(bin);
}

function mailB64ToUint8(b64) {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

function mailHexToUint8(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

async function mailSha256(input) {
  const data = typeof input === 'string' ? new TextEncoder().encode(input) : input;
  return new Uint8Array(await crypto.subtle.digest('SHA-256', data));
}

async function mailImportAesKey(material) {
  const raw = await mailSha256(material);
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

async function mailImportHmacKey(material) {
  const raw = await mailSha256(material);
  return crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

async function mailAesGcmEncrypt(key, data) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
  return { iv: mailUint8ToB64(iv), ct: mailUint8ToB64(new Uint8Array(ct)) };
}

async function mailAesGcmDecrypt(key, block) {
  const iv = mailB64ToUint8(block.iv);
  const ct = mailB64ToUint8(block.ct);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return new Uint8Array(pt);
}

function mailPersonaContext(email) {
  const pid = Object.keys(demoPersonas).find(id => getCorporateEmail(id) === email);
  const p = demoPersonas[pid];
  return { agency: p?.group || 'ЕПСОК', region: p?.region || '—' };
}

async function mailWrapLayer(keyMaterial, payloadBytes, label) {
  const key = await mailImportAesKey(keyMaterial);
  const block = await mailAesGcmEncrypt(key, payloadBytes);
  return { layer: label, block };
}

async function mailUnwrapLayer(keyMaterial, block) {
  const key = await mailImportAesKey(keyMaterial);
  return mailAesGcmDecrypt(key, block);
}

async function mailSealMulti(plaintext, opts) {
  const { recipientLogin, senderLogin, messageId, classification = 'standard' } = opts;
  const cls = MAIL_CLASSIFICATION[classification] || MAIL_CLASSIFICATION.standard;
  const senderEmail = `${senderLogin}@epsok.gov.ru`;
  const recipientEmail = `${recipientLogin}@epsok.gov.ru`;
  const senderCtx = mailPersonaContext(senderEmail);
  const recipientCtx = mailPersonaContext(recipientEmail);
  const plainBytes = new TextEncoder().encode(plaintext);
  const appliedLayers = [];

  // L1 — сквозное шифрование для получателя
  const l1Key = `epsok:mail:L1:e2e:${recipientLogin}:${messageId}`;
  let payload = new TextEncoder().encode(JSON.stringify(
    await mailWrapLayer(l1Key, plainBytes, 'L1')
  ));
  appliedLayers.push('L1');

  // L2 — VKO между отправителем и получателем
  const l2Key = `epsok:mail:L2:vko:${senderLogin}:${recipientLogin}:${messageId}`;
  payload = new TextEncoder().encode(JSON.stringify(
    await mailWrapLayer(l2Key, payload, 'L2')
  ));
  appliedLayers.push('L2');

  // L2+ — дополнительные контуры для служебного / ДСП
  if (cls.extras.includes('agency')) {
    const agencyKey = `epsok:mail:L2a:agency:${senderCtx.agency}:${messageId}`;
    payload = new TextEncoder().encode(JSON.stringify(
      await mailWrapLayer(agencyKey, payload, 'L2+agency')
    ));
    appliedLayers.push('L2+');
  }
  if (cls.extras.includes('regional')) {
    const regionKey = `epsok:mail:L2b:region:${recipientCtx.region}:${messageId}`;
    payload = new TextEncoder().encode(JSON.stringify(
      await mailWrapLayer(regionKey, payload, 'L2+region')
    ));
    if (!appliedLayers.includes('L2+')) appliedLayers.push('L2+');
  }

  // L3 — at-rest HSM платформы
  const l3Key = `${MAIL_PLATFORM_KEY_SEED}:L3:${messageId}`;
  const outer = await mailWrapLayer(l3Key, payload, 'L3');
  appliedLayers.push('L3');

  // L4 — HMAC целостности
  const envelopeCore = {
    v: MAIL_CRYPTO_VERSION,
    classification,
    messageId,
    senderLogin,
    recipientLogin,
    outer: outer.block
  };
  const hmacKey = await mailImportHmacKey(`epsok:mail:L4:hmac:${recipientLogin}:${messageId}`);
  const sigBuf = await crypto.subtle.sign(
    'HMAC',
    hmacKey,
    new TextEncoder().encode(JSON.stringify(envelopeCore))
  );
  const hmac = [...new Uint8Array(sigBuf)].map(b => b.toString(16).padStart(2, '0')).join('');
  appliedLayers.push('L4');

  const envelope = { ...envelopeCore, hmac };
  const bodySealed = mailUint8ToB64(new TextEncoder().encode(JSON.stringify(envelope)));

  const streebogDemo = (await mailSha256(JSON.stringify(envelopeCore))).slice(0, 16);
  const integrity = [...streebogDemo].map(b => b.toString(16).padStart(2, '0')).join('');

  return {
    bodySealed,
    integrity,
    hmac: hmac.slice(0, 32),
    cryptoVersion: MAIL_CRYPTO_VERSION,
    classification,
    cryptoLayers: appliedLayers,
    cryptoLayerCount: appliedLayers.length
  };
}

async function mailOpenMulti(bodySealed, opts) {
  const { recipientLogin, senderLogin, messageId, classification = 'standard' } = opts;
  const cls = MAIL_CLASSIFICATION[classification] || MAIL_CLASSIFICATION.standard;

  let envelope;
  try {
    envelope = JSON.parse(new TextDecoder().decode(mailB64ToUint8(bodySealed)));
  } catch {
    throw new Error('invalid envelope');
  }
  if (envelope.v !== MAIL_CRYPTO_VERSION) throw new Error('unsupported version');

  const hmacKey = await mailImportHmacKey(`epsok:mail:L4:hmac:${recipientLogin}:${messageId}`);
  const core = {
    v: envelope.v,
    classification: envelope.classification,
    messageId: envelope.messageId,
    senderLogin: envelope.senderLogin,
    recipientLogin: envelope.recipientLogin,
    outer: envelope.outer
  };
  const sigOk = await crypto.subtle.verify(
    'HMAC',
    hmacKey,
    mailHexToUint8(envelope.hmac),
    new TextEncoder().encode(JSON.stringify(core))
  );
  if (!sigOk) throw new Error('integrity check failed');

  const senderEmail = `${senderLogin}@epsok.gov.ru`;
  const recipientEmail = `${recipientLogin}@epsok.gov.ru`;
  const senderCtx = mailPersonaContext(senderEmail);
  const recipientCtx = mailPersonaContext(recipientEmail);

  const l3Key = `${MAIL_PLATFORM_KEY_SEED}:L3:${messageId}`;
  let payload = await mailUnwrapLayer(l3Key, envelope.outer);

  if (cls.extras.includes('regional')) {
    const regionKey = `epsok:mail:L2b:region:${recipientCtx.region}:${messageId}`;
    const wrapped = JSON.parse(new TextDecoder().decode(payload));
    payload = await mailUnwrapLayer(regionKey, wrapped.block);
  }
  if (cls.extras.includes('agency')) {
    const agencyKey = `epsok:mail:L2a:agency:${senderCtx.agency}:${messageId}`;
    const wrapped = JSON.parse(new TextDecoder().decode(payload));
    payload = await mailUnwrapLayer(agencyKey, wrapped.block);
  }

  const l2Key = `epsok:mail:L2:vko:${senderLogin}:${recipientLogin}:${messageId}`;
  let l2wrapped = JSON.parse(new TextDecoder().decode(payload));
  payload = await mailUnwrapLayer(l2Key, l2wrapped.block);

  const l1Key = `epsok:mail:L1:e2e:${recipientLogin}:${messageId}`;
  const l1wrapped = JSON.parse(new TextDecoder().decode(payload));
  const plainBytes = await mailUnwrapLayer(l1Key, l1wrapped.block);
  return new TextDecoder().decode(plainBytes);
}

async function mailSeal(plaintext, recipientLogin, senderLogin, messageId, classification) {
  return mailSealMulti(plaintext, { recipientLogin, senderLogin, messageId, classification });
}

async function mailOpen(bodySealed, recipientLogin, senderLogin, messageId, classification) {
  return mailOpenMulti(bodySealed, { recipientLogin, senderLogin, messageId, classification });
}

function mailLoginFromEmail(email) {
  return (email || '').split('@')[0];
}

function mailCiphertextPreview(bodySealed) {
  try {
    const raw = mailB64ToUint8(bodySealed);
    const envelope = JSON.parse(new TextDecoder().decode(raw));
    const ct = envelope.outer?.ct || '';
    const bin = mailB64ToUint8(ct);
    const hex = [...bin.slice(0, 24)].map(b => b.toString(16).padStart(2, '0')).join(' ');
    const layers = envelope.classification ? (MAIL_CLASSIFICATION[envelope.classification]?.layers || 4) : 4;
    return `L3 (HSM) · ${hex} … · ${bin.length} байт · ${layers} уровней`;
  } catch {
    try {
      const bin = atob(bodySealed);
      const hex = [...bin.slice(0, 24)].map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join(' ');
      return `${hex} … (${bin.length} байт)`;
    } catch {
      return '—';
    }
  }
}

function renderMailCryptoLayersHtml(msg) {
  const cls = MAIL_CLASSIFICATION[msg.classification || 'standard'] || MAIL_CLASSIFICATION.standard;
  const active = new Set(msg.cryptoLayers || ['L1', 'L2', 'L3', 'L4']);
  return `<div class="mail-crypto-stack">
    ${MAIL_CRYPTO_LAYERS.map(layer => {
      const isExtra = layer.id === 'L2+' && !cls.extras.length;
      if (isExtra) return '';
      const on = active.has(layer.id) || (layer.id === 'L2+' && active.has('L2+'));
      return `<div class="mail-crypto-layer ${on ? 'active' : 'skipped'}">
        <span class="mail-crypto-layer-id">${layer.id}</span>
        <div class="mail-crypto-layer-body">
          <strong>${layer.name}</strong>
          <span class="muted">${layer.algo}</span>
          <span class="mail-crypto-layer-scope">${layer.scope}</span>
        </div>
        <span class="mail-crypto-layer-status">${on ? '✓' : '—'}</span>
      </div>`;
    }).join('')}
  </div>`;
}

function mailClassificationBadge(classification) {
  const cls = MAIL_CLASSIFICATION[classification || 'standard'] || MAIL_CLASSIFICATION.standard;
  if (classification === 'standard') return '';
  return `<span class="mail-class-badge ${cls.badge}">${cls.label} · ${cls.layers} ур.</span>`;
}

function getCurrentMailEmail() {
  const p = getActivePersona();
  return getCorporateEmail(p.id);
}

function getCurrentMailLogin() {
  return mailLoginFromEmail(getCurrentMailEmail());
}

function getMailAddressbook() {
  const entries = new Map();
  corpMailSystemContacts.forEach(c => entries.set(c.email, c));
  Object.keys(demoPersonas).forEach(id => {
    const email = getCorporateEmail(id);
    const p = demoPersonas[id];
    if (!entries.has(email)) {
      entries.set(email, {
        email,
        name: p.name,
        agency: p.group,
        certFp: getPresence(id).cert?.replace('ESIA-', 'E') + '…' || '—'
      });
    }
  });
  return [...entries.values()].sort((a, b) => a.name.localeCompare(b.name, 'ru'));
}

function findMailContact(email) {
  return getMailAddressbook().find(c => c.email === email) || {
    email,
    name: email,
    agency: '—',
    certFp: '—'
  };
}

async function sealMailMessage(msg, recipientEmail) {
  const { plain, ...rest } = msg;
  const recipientLogin = mailLoginFromEmail(recipientEmail);
  const senderLogin = mailLoginFromEmail(msg.from);
  const sealed = await mailSeal(plain, recipientLogin, senderLogin, msg.id, msg.classification || 'standard');
  return {
    ...rest,
    bodySealed: sealed.bodySealed,
    sealedFor: recipientLogin,
    integrity: sealed.integrity,
    hmac: sealed.hmac,
    cryptoVersion: sealed.cryptoVersion,
    classification: sealed.classification,
    cryptoLayers: sealed.cryptoLayers,
    cryptoLayerCount: sealed.cryptoLayerCount
  };
}

async function prepareCorpMailThreads(threads) {
  const prepared = [];
  for (const thr of threads) {
    const messages = [];
    for (const msg of thr.messages) {
      const copies = [];
      for (const to of msg.to) {
        copies.push(await sealMailMessage({ ...msg }, to));
      }
      const senderLogin = mailLoginFromEmail(msg.from);
      const senderCopy = await sealMailMessage({ ...msg }, senderLogin);
      senderCopy.folderCopy = 'sent';
      senderCopy.read = true;
      copies.push(senderCopy);
      messages.push({ raw: msg, copies });
    }
    prepared.push({ id: thr.id, subject: thr.subject, messages });
  }
  return prepared;
}

function loadCorpMailState() {
  return null;
}

async function loadCorpMailStateSecure() {
  if (typeof EpsokSecurity !== 'undefined') {
    const data = await EpsokSecurity.secureGetItem(sessionStorage, MAIL_STORAGE_KEY);
    if (data) return data;
  }
  try {
    const raw = sessionStorage.getItem(MAIL_STORAGE_KEY);
    if (raw && !raw.startsWith('epsok:enc:')) return JSON.parse(raw);
  } catch { /* ignore */ }
  return null;
}

async function saveCorpMailState() {
  if (typeof EpsokSecurity !== 'undefined') {
    await EpsokSecurity.secureSetItem(sessionStorage, MAIL_STORAGE_KEY, corpMailThreads);
    return;
  }
  sessionStorage.setItem(MAIL_STORAGE_KEY, JSON.stringify(corpMailThreads));
}

async function resetCorpMailState() {
  corpMailReady = false;
  corpMailThreads = [];
  try {
    sessionStorage.removeItem(MAIL_STORAGE_KEY);
  } catch { /* ignore */ }
  corpMailThreads = await prepareCorpMailThreads(corpMailSeedPlain);
  await saveCorpMailState();
  corpMailReady = true;
}

function isValidCorpMailThreads(data) {
  return Array.isArray(data) && data.length > 0 && data.every(
    thr => thr && Array.isArray(thr.messages) && thr.messages.every(m => Array.isArray(m.copies))
  );
}

async function ensureCorpMailReady() {
  if (corpMailReady && corpMailThreads.length) return;
  try {
    const stored = await loadCorpMailStateSecure();
    if (isValidCorpMailThreads(stored)) {
      corpMailThreads = stored;
      corpMailReady = true;
      return;
    }
    await resetCorpMailState();
  } catch (err) {
    console.error(err);
    await resetCorpMailState();
  }
}

function getMailThreadsGrouped() {
  const login = getCurrentMailLogin();
  const email = getCurrentMailEmail();
  const map = new Map();
  corpMailThreads.forEach(thr => {
    thr.messages.forEach(bundle => {
      bundle.copies.forEach(copy => {
        const inbox = copy.sealedFor === login && copy.to?.includes(email) && copy.folderCopy !== 'sent';
        const sent = copy.from === email && copy.folderCopy === 'sent' && copy.sealedFor === login;
        const include = mailFolder === 'inbox' ? inbox : sent;
        if (!include) return;
        if (!map.has(thr.id)) map.set(thr.id, { thread: thr, latest: copy });
        else if ((copy.at || '') > (map.get(thr.id).latest.at || '')) map.get(thr.id).latest = copy;
      });
    });
  });
  return [...map.values()].sort((a, b) => (b.latest.at || '').localeCompare(a.latest.at || '', 'ru'));
}

function getUnreadMailCount() {
  const login = getCurrentMailLogin();
  const email = getCurrentMailEmail();
  let count = 0;
  corpMailThreads.forEach(thr => {
    thr.messages.forEach(bundle => {
      bundle.copies.forEach(copy => {
        if (copy.sealedFor === login && copy.to?.includes(email) && copy.folderCopy !== 'sent' && !copy.read) count += 1;
      });
    });
  });
  return count;
}

function updateMailSidebarBadge() {
  const badge = document.getElementById('sidebar-corp-mail-badge');
  if (!badge) return;
  const n = corpMailReady ? getUnreadMailCount() : 0;
  badge.textContent = String(n);
  badge.classList.toggle('hidden', n === 0);
}

function openCorpMail(opts = {}) {
  if (opts.to) mailComposeTo = opts.to;
  if (opts.threadId) activeMailThreadId = opts.threadId;
  showView('mail');
  if (opts.compose) {
    setTimeout(() => openMailCompose(opts.to, opts.subject), 50);
  }
}

function openCorpMailTo(email, subject) {
  openCorpMail({ to: email, subject, compose: true });
}

function setMailFolder(folder) {
  mailFolder = folder;
  activeMailThreadId = null;
  renderCorpMail();
}

function selectMailThread(threadId) {
  activeMailThreadId = threadId;
  const login = getCurrentMailLogin();
  const email = getCurrentMailEmail();
  corpMailThreads.forEach(thr => {
    if (thr.id !== threadId) return;
    thr.messages.forEach(bundle => {
      bundle.copies.forEach(copy => {
        if (copy.sealedFor === login && copy.to?.includes(email) && !copy.read) copy.read = true;
      });
    });
  });
  saveCorpMailState();
  updateMailSidebarBadge();
  renderCorpMail();
}

async function renderCorpMailMessageBody(msg) {
  if (!msg.bodySealed) return escapeHtml(msg.plain || '—');
  try {
    const plain = await mailOpen(
      msg.bodySealed,
      msg.sealedFor || getCurrentMailLogin(),
      mailLoginFromEmail(msg.from),
      msg.id,
      msg.classification || 'standard'
    );
    return escapeHtml(plain).replace(/\n/g, '<br>');
  } catch {
    return '<span class="muted">Ошибка расшифровки. Проверьте ГОСТ-токен и уровень доступа.</span>';
  }
}

async function renderCorpMailDetail(threadId) {
  const login = getCurrentMailLogin();
  const email = getCurrentMailEmail();
  const thr = corpMailThreads.find(t => t.id === threadId);
  if (!thr) return '<p class="muted">Выберите сообщение</p>';

  const msgs = [];
  thr.messages.forEach(bundle => {
    bundle.copies.forEach(copy => {
      const inbox = copy.sealedFor === login && copy.to?.includes(email) && copy.folderCopy !== 'sent';
      const sent = copy.from === email && copy.folderCopy === 'sent' && copy.sealedFor === login;
      if ((mailFolder === 'inbox' && inbox) || (mailFolder === 'sent' && sent)) msgs.push(copy);
    });
  });
  msgs.sort((a, b) => (a.at || '').localeCompare(b.at || '', 'ru'));

  const blocks = await Promise.all(msgs.map(async (msg) => {
    const bodyHtml = await renderCorpMailMessageBody(msg);
    const contact = findMailContact(msg.from);
    const adminCrypto = canViewMailCryptoAdmin();
    const cryptoDetails = adminCrypto ? `<details class="mail-crypto-details">
        <summary>Криптографическая информация · ${msg.cryptoLayerCount || 4} уровней</summary>
        ${renderMailCryptoLayersHtml(msg)}
        <dl class="mail-crypto-dl">
          <div><dt>Версия конверта</dt><dd><code>E${msg.cryptoVersion || MAIL_CRYPTO_VERSION}</code></dd></div>
          <div><dt>Сертификат отправителя</dt><dd><code>${escapeHtml(msg.certFp || contact.certFp)}</code></dd></div>
          <div><dt>Ключ сессии</dt><dd><code>${escapeHtml(msg.keyId || '—')}</code></dd></div>
          <div><dt>HMAC (L4)</dt><dd><code>${escapeHtml(msg.hmac || msg.integrity || '—')}</code></dd></div>
          <div><dt>Streebog-256 (демо)</dt><dd><code>${escapeHtml(msg.integrity || '—')}</code></dd></div>
          <div><dt>Перехват канала</dt><dd class="mail-cipher-preview"><code>${escapeHtml(mailCiphertextPreview(msg.bodySealed))}</code></dd></div>
        </dl>
        <p class="muted mail-crypto-note">Транспорт: ГОСТ TLS 1.3 · содержимое: ${msg.cryptoLayerCount || 4} уровней AES-GCM + HMAC. Без ключей ЕСИА/HSM расшифровка невозможна.</p>
      </details>` : '';
    const secureBadge = adminCrypto
      ? `<span class="mail-badge-secure">⛨ ${msg.cryptoLayerCount || 4}-уровневое шифрование</span>`
      : `<span class="mail-badge-secure">⛨ Защищённое сообщение</span>`;
    return `<article class="mail-message ${msg.read === false ? 'unread' : ''}">
      <header class="mail-message-head">
        <div>
          <strong>${escapeHtml(msg.fromName || contact.name)}</strong>
          <span class="muted">${escapeHtml(msg.from)}</span>
        </div>
        <time class="muted">${escapeHtml(msg.at)}</time>
      </header>
      <h4 class="mail-message-subject">${escapeHtml(msg.subject)} ${mailClassificationBadge(msg.classification)}</h4>
      <div class="mail-message-body">${bodyHtml}</div>
      ${cryptoDetails}
      <div class="mail-message-badges">
        ${secureBadge}
        <span class="mail-badge-verified">✓ Подпись ЕСИА</span>
        ${msg.classification === 'restricted' ? '<span class="mail-badge-restricted">ДСП</span>' : ''}
      </div>
    </article>`;
  }));

  return `<div class="mail-detail-head">
    <h3>${escapeHtml(thr.subject)}</h3>
    <button type="button" class="btn-sm" onclick="openMailCompose()">↩ Ответить</button>
  </div>
  <div class="mail-messages">${blocks.join('')}</div>`;
}

async function renderCorpMail() {
  const app = document.getElementById('mail-app');
  if (app) app.innerHTML = '<p class="muted mail-empty">Загрузка почтового ящика…</p>';
  try {
    await ensureCorpMailReady();
  } catch (err) {
    console.error(err);
    if (app) {
      app.innerHTML = '<p class="muted mail-empty">Не удалось загрузить почту. <button type="button" class="btn-sm" onclick="resetCorpMailState().then(() => renderCorpMail())">Восстановить</button></p>';
    }
    return;
  }
  syncMailAdminVisibility();
  updateMailSidebarBadge();
  if (!app) return;

  const email = getCurrentMailEmail();
  const threads = getMailThreadsGrouped();
  if (!activeMailThreadId && threads.length) activeMailThreadId = threads[0].thread.id;

  const threadList = threads.map(g => {
    const unread = mailFolder === 'inbox' && g.latest.read === false;
    const active = g.thread.id === activeMailThreadId ? ' active' : '';
    const peer = mailFolder === 'sent' ? g.latest.to?.[0] : g.latest.from;
    const peerContact = findMailContact(peer);
    return `<button type="button" class="mail-thread-btn${active}${unread ? ' unread' : ''}" onclick="selectMailThread('${g.thread.id}')">
      <span class="mail-thread-peer">${escapeHtml(peerContact.name)}</span>
      <span class="mail-thread-subject">${escapeHtml(g.thread.subject)}</span>
      <span class="mail-thread-meta"><time>${escapeHtml(g.latest.at)}</time>${unread ? '<span class="mail-unread-dot"></span>' : ''}</span>
    </button>`;
  }).join('') || '<p class="muted mail-empty">Нет сообщений</p>';

  const detailHtml = activeMailThreadId
    ? await renderCorpMailDetail(activeMailThreadId)
    : '<p class="muted mail-empty">Выберите сообщение из списка</p>';

  app.innerHTML = `
    <aside class="mail-sidebar">
      <button type="button" class="btn-primary mail-compose-btn" onclick="openMailCompose()">+ Написать</button>
      <nav class="mail-folders">
        <button type="button" class="mail-folder-btn ${mailFolder === 'inbox' ? 'active' : ''}" onclick="setMailFolder('inbox')">
          Входящие <span class="mail-folder-count">${getUnreadMailCount() || ''}</span>
        </button>
        <button type="button" class="mail-folder-btn ${mailFolder === 'sent' ? 'active' : ''}" onclick="setMailFolder('sent')">Отправленные</button>
      </nav>
      <p class="mail-sidebar-label">Ящик</p>
      <p class="mail-sidebar-email mono">${escapeHtml(email)}</p>
    </aside>
    <div class="mail-threads">${threadList}</div>
    <div class="mail-detail" id="mail-detail">${detailHtml}</div>`;

  const datalist = document.getElementById('mail-addressbook');
  if (datalist) {
    datalist.innerHTML = getMailAddressbook()
      .filter(c => c.email !== email)
      .map(c => `<option value="${escapeHtml(c.email)}">${escapeHtml(c.name)} · ${escapeHtml(c.agency)}</option>`)
      .join('');
  }
}

function openMailCompose(to, subject) {
  const modal = document.getElementById('mail-compose-modal');
  const toEl = document.getElementById('mail-compose-to');
  const subEl = document.getElementById('mail-compose-subject');
  const bodyEl = document.getElementById('mail-compose-body');
  let replyTo = to;
  if (!replyTo && activeMailThreadId) {
    const thr = corpMailThreads.find(t => t.id === activeMailThreadId);
    const login = getCurrentMailLogin();
    const email = getCurrentMailEmail();
    for (const bundle of thr?.messages || []) {
      for (const copy of bundle.copies) {
        if (copy.sealedFor === login && copy.to?.includes(email) && copy.folderCopy !== 'sent') {
          replyTo = copy.from;
          break;
        }
      }
      if (replyTo) break;
    }
  }
  if (toEl) toEl.value = replyTo || mailComposeTo || '';
  if (subEl) subEl.value = subject || (activeMailThreadId ? `Re: ${corpMailThreads.find(t => t.id === activeMailThreadId)?.subject || ''}` : '');
  if (bodyEl) bodyEl.value = '';
  const clsEl = document.getElementById('mail-compose-classification');
  if (clsEl) clsEl.value = 'standard';
  mailComposeTo = null;
  modal?.classList.remove('hidden');
  syncMailAdminVisibility();
  updateMailComposeCryptoPreview();
}

function closeMailCompose() {
  document.getElementById('mail-compose-modal')?.classList.add('hidden');
}

async function updateMailComposeCryptoPreview() {
  const preview = document.getElementById('mail-compose-crypto-preview');
  if (!preview) return;
  if (!canViewMailCryptoAdmin()) {
    preview.innerHTML = '';
    return;
  }
  const to = document.getElementById('mail-compose-to')?.value.trim();
  const body = document.getElementById('mail-compose-body')?.value || '';
  const classification = document.getElementById('mail-compose-classification')?.value || 'standard';
  if (!to || !body) {
    preview.innerHTML = '<span class="muted">Введите адресата и текст — будет показан стек уровней шифрования и шифротекст до отправки.</span>';
    return;
  }
  const recipientLogin = mailLoginFromEmail(to);
  const senderLogin = getCurrentMailLogin();
  const sealed = await mailSealMulti(body, {
    recipientLogin,
    senderLogin,
    messageId: '__compose-preview__',
    classification
  });
  const cls = MAIL_CLASSIFICATION[classification] || MAIL_CLASSIFICATION.standard;
  const layerPreview = { classification, cryptoLayers: sealed.cryptoLayers };
  preview.innerHTML = `<span class="mail-badge-secure">⛨ ${sealed.cryptoLayerCount}-уровневое шифрование · ${escapeHtml(cls.label)} · ${escapeHtml(to)}</span>
    ${renderMailCryptoLayersHtml(layerPreview)}
    <code class="mail-cipher-preview">${escapeHtml(mailCiphertextPreview(sealed.bodySealed))}</code>`;
}

async function submitCorpMailSend(e) {
  e.preventDefault();
  await ensureCorpMailReady();
  const to = document.getElementById('mail-compose-to')?.value.trim().toLowerCase();
  const subject = document.getElementById('mail-compose-subject')?.value.trim();
  const body = document.getElementById('mail-compose-body')?.value.trim();
  const classification = document.getElementById('mail-compose-classification')?.value || 'standard';
  if (!to || !subject || !body) return;

  const fromEmail = getCurrentMailEmail();
  const fromName = getActivePersona().name;
  const cls = MAIL_CLASSIFICATION[classification] || MAIL_CLASSIFICATION.standard;
  const now = new Date();
  const at = `${String(now.getDate()).padStart(2, '0')}.${String(now.getMonth() + 1).padStart(2, '0')}.${now.getFullYear()} ${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}`;

  const raw = {
    id: `msg-${Date.now()}`,
    from: fromEmail,
    fromName,
    to: [to],
    at,
    subject,
    plain: body,
    classification,
    keyId: getPresence(getActivePersona().id).cert || 'ESIA-DEMO',
    certFp: 'LIVE…' + Math.random().toString(16).slice(2, 6).toUpperCase(),
    read: true
  };

  const recipientCopy = await sealMailMessage(raw, to);
  const senderCopy = await sealMailMessage(raw, getCurrentMailLogin());
  senderCopy.folderCopy = 'sent';

  let thr = corpMailThreads.find(t => t.subject === subject || t.id === activeMailThreadId);
  if (!thr) {
    thr = { id: `thr-${Date.now()}`, subject, messages: [] };
    corpMailThreads.unshift(thr);
  }
  thr.messages.push({ raw, copies: [recipientCopy, senderCopy] });
  activeMailThreadId = thr.id;
  mailFolder = 'sent';
  saveCorpMailState();
  closeMailCompose();
  showToast(`${cls.layers}-уровневое шифрование · сообщение отправлено · ${to}`);
  renderCorpMail();
}

function corpMailLinkHtml(email, label) {
  const text = label || email;
  const safe = email.replace(/\\/g, '\\\\').replace(/'/g, "\\'");
  return `<button type="button" class="st-mail-link" onclick="openCorpMailTo('${safe}')">${escapeHtml(text)}</button>`;
}

// --- Реестр дел ---

let activeCaseId = 'ЕПСОК-2028-004521';

const caseStatusLabels = {
  investigating: 'Расследуется',
  inquiry: 'Дознание',
  suspended: 'Приостановлено',
  court: 'Направлено в суд'
};

const CASES_FILTER_ALL = '__ALL__';

function isCasesFilterAll(value) {
  return value === CASES_FILTER_ALL;
}

function formatDepartmentFilterLabel(value) {
  return isCasesFilterAll(value) ? 'Все отделы' : value;
}

function formatAgencyFilterLabel(code) {
  return isCasesFilterAll(code) ? 'Все ведомства' : getAgencyDisplayName(code);
}

const casesRegistry = [
  {
    id: 'ЕПСОК-2028-004521',
    region: 'Краснодарский край',
    department: 'СО №3 по Центральному району',
    agency: 'МВД',
    agencyName: 'МВД России',
    article: '159.3 УК РФ',
    crimeType: 'Мошенничество',
    status: 'investigating',
    stage: 'Следствие',
    lead: 'Иванов С.П.',
    managers: ['INV_MVD', 'INV_LEAD_MVD'],
    opened: '14.01.2028',
    daysLeft: 2,
    cluster: 'МВ-2847',
    timeline: [
      { date: '12.01.2028', text: 'Заявление потерпевшего (СОДЧ)' },
      { date: '14.01.2028', text: 'Возбуждено уголовное дело' },
      { date: '20.01.2028', text: 'Допрос потерпевшего' },
      { date: '02.02.2028', text: 'Запрос в Росфинмониторинг' },
      { date: '05.02.2028', text: 'Установлена связь с делом ЕПСОК-2028-001234 (Москва · 159.3 УК · мошенничество)', highlight: true },
      { date: '10.02.2028', text: 'Обыск, изъятие цифровых носителей' },
      { date: '12.06.2028', text: 'Открытые источники: почта → 4 аккаунта, 2 телефона', highlight: true, osint: true }
    ],
    team: [
      { name: 'Иванов С.П.', role: 'следователь (ответственный)' },
      { name: 'Ковалёв Д.М.', role: 'следователь (соисполнитель)' },
      { name: 'Петрова А.К.', role: 'следователь СК (смежное дело)' },
      { name: 'Сидоров М.В.', role: 'оперуполномоченный' }
    ],
    related: [
      { id: 'ЕПСОК-2028-001234', place: 'Москва', article: '159.3 УК', title: 'Мошенничество', link: 'связь по счёту' },
      { id: 'ЕПСОК-2028-002891', place: 'Республика Татарстан', article: '159.3 УК', title: 'Мошенничество', link: 'связь по SIM' }
    ]
  },
  {
    id: 'ЕПСОК-2028-001234',
    region: 'Москва',
    department: 'СУ по ЮВАО',
    agency: 'СК',
    agencyName: 'СК РФ',
    article: '159.3 УК РФ',
    crimeType: 'Мошенничество',
    status: 'investigating',
    stage: 'Следствие',
    lead: 'Петрова А.К.',
    managers: ['INV_SK', 'INV_LEAD_SK'],
    opened: '08.12.2027',
    daysLeft: 18,
    cluster: 'МВ-2847',
    timeline: [
      { date: '08.12.2027', text: 'Возбуждено дело' },
      { date: '15.01.2028', text: 'Запрос в РФМ по счёту' },
      { date: '05.02.2028', text: 'Связь с делом Краснодар (ЕПСОК-004521)', highlight: true }
    ],
    team: [{ name: 'Петрова А.К.', role: 'следователь (ответственный)' }, { name: 'Григорьева М.Н.', role: 'следователь (соисполнитель)' }],
    related: [{ id: 'ЕПСОК-2028-004521', place: 'Краснодарский край', article: '159.3 УК', title: 'Мошенничество', link: 'связь по счёту' }]
  },
  {
    id: 'ЕПСОК-2028-002891',
    region: 'Республика Татарстан',
    department: 'СО по Приволжскому району',
    agency: 'МВД',
    agencyName: 'МВД России',
    article: '159.3 УК РФ',
    crimeType: 'Мошенничество',
    status: 'investigating',
    stage: 'Следствие',
    lead: 'Гарифуллин Р.Н.',
    managers: [],
    opened: '22.01.2028',
    daysLeft: 11,
    cluster: 'МВ-2847',
    timeline: [
      { date: '22.01.2028', text: 'Возбуждено дело' },
      { date: '14.03.2028', text: 'Совпадение SIM с кластером МВ-2847', highlight: true }
    ],
    team: [{ name: 'Гарифуллин Р.Н.', role: 'следователь' }],
    related: [{ id: 'ЕПСОК-2028-004521', place: 'Краснодарский край', article: '159.3 УК', title: 'Мошенничество', link: 'связь по SIM' }]
  },
  {
    id: 'ЕПСОК-2028-003891',
    region: 'Краснодарский край',
    department: 'СО №3 по Центральному району',
    agency: 'МВД',
    agencyName: 'МВД России',
    article: '158 УК РФ',
    crimeType: 'Кража',
    status: 'inquiry',
    stage: 'Дознание',
    lead: 'Ковалёв Д.М.',
    managers: ['INV_MVD_KOVALEV'],
    opened: '03.03.2028',
    daysLeft: 5,
    timeline: [{ date: '03.03.2028', text: 'Возбуждено дело' }],
    team: [{ name: 'Ковалёв Д.М.', role: 'следователь (ответственный)' }],
    related: []
  },
  {
    id: 'ЕПСОК-2028-005102',
    region: 'Краснодарский край',
    department: 'СО №1 по Прикубанскому району',
    agency: 'МВД',
    agencyName: 'МВД России',
    article: '105 УК РФ',
    crimeType: 'Убийство',
    status: 'investigating',
    stage: 'Следствие',
    lead: 'Морозова Е.А.',
    opened: '18.04.2028',
    daysLeft: 6,
    timeline: [{ date: '18.04.2028', text: 'Возбуждено дело' }],
    team: [{ name: 'Морозова Е.А.', role: 'следователь' }],
    related: []
  },
  {
    id: 'ЕПСОК-2028-003412',
    region: 'Ростовская область',
    department: 'СО по Ленинскому району',
    agency: 'СК',
    agencyName: 'СК РФ',
    article: '159.3 УК РФ',
    crimeType: 'Мошенничество',
    status: 'investigating',
    stage: 'Следствие',
    lead: 'Белова О.С.',
    opened: '11.02.2028',
    daysLeft: 14,
    cluster: 'МВ-2847',
    timeline: [{ date: '11.02.2028', text: 'Возбуждено дело' }],
    team: [{ name: 'Белова О.С.', role: 'следователь' }],
    related: []
  },
  {
    id: 'ЕПСОК-2028-006201',
    region: 'Москва',
    department: 'ГСУ по экономике',
    agency: 'СК',
    agencyName: 'СК РФ',
    article: '199 УК РФ',
    crimeType: 'Злоупотребление должностными полномочиями',
    status: 'investigating',
    stage: 'Следствие',
    lead: 'Смирнов Д.А.',
    opened: '25.05.2028',
    daysLeft: 22,
    timeline: [{ date: '25.05.2028', text: 'Возбуждено дело' }],
    team: [{ name: 'Смирнов Д.А.', role: 'следователь (ответственный)' }, { name: 'Борисов А.С.', role: 'следователь (соисполнитель)' }],
    related: []
  },
  {
    id: 'ЕПСОК-2028-002105',
    region: 'Ставропольский край',
    department: 'ОУР №4',
    agency: 'МВД',
    agencyName: 'МВД России',
    article: '161 УК РФ',
    crimeType: 'Грабёж',
    status: 'inquiry',
    stage: 'Дознание',
    lead: 'Абрамов П.К.',
    opened: '09.01.2028',
    daysLeft: 9,
    timeline: [{ date: '09.01.2028', text: 'Возбуждено дело' }],
    team: [{ name: 'Никитин Р.О.', role: 'руководитель ОУР' }, { name: 'Абрамов К.Д.', role: 'оперуполномоченный' }, { name: 'Чернова Е.В.', role: 'оперуполномоченный' }],
    related: []
  },
  {
    id: 'ЕПСОК-2028-007044',
    region: 'Республика Татарстан',
    department: 'СО по Московскому району',
    agency: 'СК',
    agencyName: 'СК РФ',
    article: '222.1 УК РФ',
    crimeType: 'Незаконный оборот оружия',
    status: 'investigating',
    stage: 'Следствие',
    lead: 'Хасанов И.М.',
    opened: '30.04.2028',
    daysLeft: 16,
    timeline: [{ date: '30.04.2028', text: 'Возбуждено дело' }],
    team: [{ name: 'Хасанов И.М.', role: 'следователь' }],
    related: []
  },
  {
    id: 'ЕПСОК-2028-001890',
    region: 'Краснодарский край',
    department: 'МСО по Краснодарскому краю',
    agency: 'СК',
    agencyName: 'СК РФ',
    article: '286 УК РФ',
    crimeType: 'Должностные преступления',
    status: 'suspended',
    stage: 'Следствие',
    lead: 'Волкова Н.Г.',
    opened: '17.11.2027',
    daysLeft: null,
    timeline: [{ date: '17.11.2027', text: 'Возбуждено дело' }, { date: '02.04.2028', text: 'Приостановлено (розыск)' }],
    team: [{ name: 'Волкова Н.Г.', role: 'следователь' }],
    related: []
  },
  {
    id: 'ЕПСОК-2028-008311',
    region: 'Ростовская область',
    department: 'ОЭБ и ПК',
    agency: 'МВД',
    agencyName: 'МВД России',
    article: '165 УК РФ',
    crimeType: 'Присвоение / растрата',
    status: 'investigating',
    stage: 'Следствие',
    lead: 'Тихонов А.Р.',
    opened: '06.06.2028',
    daysLeft: 28,
    cluster: 'МВ-3102',
    timeline: [{ date: '06.06.2028', text: 'Возбуждено дело' }],
    team: [{ name: 'Тихонов А.Р.', role: 'следователь' }],
    related: []
  },
  {
    id: 'ЕПСОК-2028-004002',
    region: 'Москва',
    department: 'ОРЧ по особо важным делам',
    agency: 'МВД',
    agencyName: 'МВД России',
    article: '210 УК РФ',
    crimeType: 'Организация преступного сообщества',
    status: 'investigating',
    stage: 'Следствие',
    lead: 'Орлов К.В.',
    opened: '12.09.2027',
    daysLeft: 4,
    cluster: 'МВ-1923',
    timeline: [{ date: '12.09.2027', text: 'Возбуждено дело' }],
    team: [{ name: 'Орлов К.В.', role: 'следователь' }, { name: 'Лебедев М.С.', role: 'оперуполномоченный' }],
    related: []
  },
  {
    id: 'ЕПСОК-2028-005890',
    region: 'Ставропольский край',
    department: 'СО №2',
    agency: 'СК',
    agencyName: 'СК РФ',
    article: '158 УК РФ',
    crimeType: 'Кража',
    status: 'court',
    stage: 'Направлено в суд',
    lead: 'Данилов С.Ю.',
    opened: '20.08.2027',
    daysLeft: null,
    timeline: [{ date: '20.08.2027', text: 'Возбуждено дело' }, { date: '01.06.2028', text: 'Обвинительное заключение' }],
    team: [{ name: 'Данилов С.Ю.', role: 'следователь' }],
    related: []
  },
  {
    id: 'ЕПСОК-2028-009120',
    region: 'Республика Татарстан',
    department: 'ОЭБ и ПК',
    agency: 'МВД',
    agencyName: 'МВД России',
    article: '159.6 УК РФ',
    crimeType: 'Мошенничество в сфере кредитования',
    status: 'investigating',
    stage: 'Следствие',
    lead: 'Сафин А.Т.',
    opened: '28.05.2028',
    daysLeft: 19,
    timeline: [{ date: '28.05.2028', text: 'Возбуждено дело' }],
    team: [{ name: 'Сафин А.Т.', role: 'следователь' }],
    related: []
  },
  {
    id: 'ЕПСОК-2028-002667',
    region: 'Ростовская область',
    department: 'ОУР №2',
    agency: 'МВД',
    agencyName: 'МВД России',
    article: '228.1 УК РФ',
    crimeType: 'Наркотики',
    status: 'inquiry',
    stage: 'Дознание',
    lead: 'Романов И.П.',
    opened: '14.02.2028',
    daysLeft: 12,
    cluster: 'МВ-1923',
    timeline: [{ date: '14.02.2028', text: 'Возбуждено дело' }],
    team: [{ name: 'Романов И.П.', role: 'дознаватель' }],
    related: []
  },
  {
    id: 'ЕПСОК-2028-007501',
    region: 'Краснодарский край',
    department: 'УФСБ по Краснодарскому краю',
    agency: 'ФСБ',
    agencyName: 'ФСБ России',
    article: '205.1 УК РФ',
    crimeType: 'Содействие террористической деятельности',
    status: 'investigating',
    stage: 'Следствие',
    lead: 'Волков И.Н.',
    managers: ['INV_FSB', 'INV_LEAD_FSB'],
    opened: '20.05.2028',
    daysLeft: 10,
    timeline: [
      { date: '20.05.2028', text: 'Возбуждено дело' },
      { date: '02.06.2028', text: 'ОРД-материалы связаны с делом МВД-2847', highlight: true }
    ],
    team: [{ name: 'Волков И.Н.', role: 'следователь (ответственный)' }],
    related: [{ id: 'ЕПСОК-2028-004521', place: 'Краснодарский край', article: '159.3 УК', title: 'Мошенничество', link: 'общая цепочка' }]
  },
  {
    id: 'ЕПСОК-2028-008902',
    region: 'Ставропольский край',
    department: 'Управление Росгвардии',
    agency: 'РОСГВАРДИЯ',
    agencyName: 'Росгвардия',
    article: '222.1 УК РФ',
    crimeType: 'Незаконный оборот оружия',
    status: 'investigating',
    stage: 'Следствие',
    lead: 'Кравцов А.Л.',
    opened: '11.04.2028',
    daysLeft: 15,
    timeline: [{ date: '11.04.2028', text: 'Возбуждено дело по факту незаконного хранения оружия' }],
    team: [{ name: 'Кравцов А.Л.', role: 'следователь (ответственный)' }, { name: 'Шишкин Г.О.', role: 'следователь (соисполнитель)' }],
    related: []
  },
  {
    id: 'ЕПСОК-2028-009330',
    region: 'Москва',
    department: 'Таможня Шереметьево',
    agency: 'ФТС',
    agencyName: 'ФТС России',
    article: '194.1 УК РФ',
    crimeType: 'Контрабанда',
    status: 'investigating',
    stage: 'Следствие',
    lead: 'Новикова Е.В.',
    opened: '03.06.2028',
    daysLeft: 21,
    cluster: 'МВ-3102',
    timeline: [{ date: '03.06.2028', text: 'Возбуждено дело · изъятие партии товара' }],
    team: [{ name: 'Новикова Е.В.', role: 'следователь таможни (ответственный)' }, { name: 'Жукова А.Р.', role: 'руководитель отдела' }],
    related: []
  },
  {
    id: 'ЕПСОК-2028-010045',
    region: 'Краснодарский край',
    department: 'СО №2 по Карасунскому округу',
    agency: 'МВД',
    agencyName: 'МВД России',
    article: '166 УК РФ',
    crimeType: 'Хищение автомобиля',
    status: 'investigating',
    stage: 'Следствие',
    lead: 'Новиков П.С.',
    opened: '01.06.2028',
    daysLeft: 24,
    timeline: [
      { date: '01.06.2028', text: 'Возбуждено дело по факту угона' },
      { date: '10.06.2028', text: 'Ориентировка в ГИБДД · розыск ТС' }
    ],
    team: [{ name: 'Новиков П.С.', role: 'следователь (ответственный)' }],
    related: []
  },
  {
    id: 'ЕПСОК-2028-010112',
    region: 'Краснодарский край',
    department: 'СО №7 по Западному округу',
    agency: 'МВД',
    agencyName: 'МВД России',
    article: '159.2 УК РФ',
    crimeType: 'Мошенничество',
    status: 'investigating',
    stage: 'Следствие',
    lead: 'Семёнова О.Г.',
    managers: ['INV_MVD_SEMYONOVA', 'INV_LEAD_MVD_WEST'],
    opened: '08.06.2028',
    daysLeft: 20,
    cluster: 'МВ-2847',
    timeline: [
      { date: '08.06.2028', text: 'Возбуждено дело' },
      { date: '12.06.2028', text: 'Связь с кластером МВ-2847 установлена аналитикой', highlight: true }
    ],
    team: [{ name: 'Семёнова О.Г.', role: 'следователь (ответственный)' }],
    related: [{ id: 'ЕПСОК-2028-004521', place: 'Краснодарский край', article: '159.3 УК', title: 'Мошенничество', link: 'кластер МВ-2847' }]
  },
  {
    id: 'ЕПСОК-2028-010201',
    region: 'Краснодарский край',
    department: 'УФСБ по Краснодарскому краю',
    agency: 'ФСБ',
    agencyName: 'ФСБ России',
    article: '275.1 УК РФ',
    crimeType: 'Государственная измена',
    status: 'investigating',
    stage: 'Следствие',
    lead: 'Степанов М.А.',
    opened: '05.06.2028',
    daysLeft: 30,
    timeline: [{ date: '05.06.2028', text: 'Возбуждено дело · гриф «ДСП»' }],
    team: [{ name: 'Степанов М.А.', role: 'следователь (ответственный)' }, { name: 'Волков И.Н.', role: 'следователь (консультант)' }],
    related: []
  }
];

function getCaseById(id) {
  return casesRegistry.find(c => c.id === id);
}

function findPersonaIdByLeadName(leadName) {
  if (!leadName) return null;
  const entry = Object.entries(demoPersonas).find(([, p]) => p.name === leadName);
  return entry ? entry[0] : null;
}

function normalizeCaseManagers(c) {
  if (!c) return [];
  if (c.managers?.length) return [...new Set(c.managers)];
  const legacy = findPersonaIdByLeadName(c.lead);
  return legacy ? [legacy] : [];
}

function getCaseManagers(caseId) {
  const c = getCaseById(caseId);
  return normalizeCaseManagers(c);
}

function isCaseManager(personaId, caseId) {
  return getCaseManagers(caseId).includes(personaId);
}

function getCaseManagersDisplay(caseId) {
  return getCaseManagers(caseId)
    .map(id => demoPersonas[id]?.name || id)
    .filter(Boolean);
}

function canEditCaseLinks(caseId, p = getActivePersona()) {
  return !isCaseReadOnly(p) && isCaseManager(p.id, caseId);
}

function getRelatedCaseSummary(relatedId) {
  const rc = getCaseById(relatedId);
  if (!rc) return null;
  return {
    id: rc.id,
    place: rc.region,
    article: rc.article.replace(' УК РФ', ''),
    title: rc.crimeType,
    agencyName: rc.agencyName
  };
}

function enrichRelatedEntry(entry) {
  const summary = getRelatedCaseSummary(entry.id);
  return {
    ...entry,
    place: entry.place || summary?.place || '—',
    article: entry.article || summary?.article || '—',
    title: entry.title || summary?.title || '',
    agencyName: summary?.agencyName || ''
  };
}

function removeRelatedCaseLink(caseId, relatedId) {
  if (!canEditCaseLinks(caseId)) {
    showToast('Изменение связей доступно только руководителям дела.');
    return;
  }
  const c = getCaseById(caseId);
  if (!c) return;
  c.related = (c.related || []).filter(r => r.id !== relatedId);
  const other = getCaseById(relatedId);
  if (other) other.related = (other.related || []).filter(r => r.id !== caseId);
  syncGraphFromCase(c);
  appendCaseTimelineEntry(caseId, `Удалена связь с делом ${relatedId}`);
  showToast(`Связь с ${relatedId} снята`);
  renderCaseDetail(caseId);
}

function addRelatedCaseLink(caseId) {
  if (!canEditCaseLinks(caseId)) {
    showToast('Изменение связей доступно только руководителям дела.');
    return;
  }
  const c = getCaseById(caseId);
  if (!c) return;
  const select = document.getElementById('related-case-add-select');
  const linkInput = document.getElementById('related-case-add-link');
  const relatedId = select?.value;
  const linkType = linkInput?.value.trim() || 'связь по материалам';
  if (!relatedId) { showToast('Выберите дело для связи.'); return; }
  if (relatedId === caseId) { showToast('Нельзя связать дело с самим собой.'); return; }
  const summary = getRelatedCaseSummary(relatedId);
  if (!summary) { showToast('Дело не найдено в реестре.'); return; }
  c.related = c.related || [];
  if (c.related.some(r => r.id === relatedId)) { showToast('Связь уже установлена.'); return; }
  const entry = {
    id: relatedId,
    place: summary.place,
    article: summary.article,
    title: summary.title,
    link: linkType
  };
  c.related.push(entry);
  const other = getCaseById(relatedId);
  if (other) {
    other.related = other.related || [];
    if (!other.related.some(r => r.id === caseId)) {
      other.related.push({
        id: caseId,
        place: c.region,
        article: c.article.replace(' УК РФ', ''),
        title: c.crimeType,
        link: linkType
      });
      syncGraphFromCase(other);
    }
  }
  syncGraphFromCase(c);
  appendCaseTimelineEntry(caseId, `Установлена связь с делом ${relatedId} (${summary.place})`, { highlight: true });
  showToast(`Связь с ${relatedId} добавлена`);
  renderCaseDetail(caseId);
}

function renderRelatedCasesSection(c) {
  const canEdit = canEditCaseLinks(c.id);
  const related = (c.related || []).map(enrichRelatedEntry);
  const itemsHtml = related.length
    ? related.map(r => `
      <li class="related-case-item">
        <div class="related-case-main">
          <button type="button" class="case-link" onclick="openCase('${r.id}')">${escapeHtml(r.id)}</button>
          <span class="related-case-title">${escapeHtml(r.title || '—')}</span>
          <span class="related-case-meta">${escapeHtml(r.place)} · ${escapeHtml(r.article)}${r.agencyName ? ` · ${escapeHtml(r.agencyName)}` : ''}</span>
          <span class="link-badge">${escapeHtml(r.link)}</span>
        </div>
        ${canEdit ? `<button type="button" class="btn-xs reject related-case-remove" onclick="removeRelatedCaseLink('${c.id}','${r.id}')" title="Удалить связь">✕</button>` : ''}
      </li>
    `).join('')
    : '<li class="muted">Похожих дел не зафиксировано</li>';

  const linkedIds = new Set([c.id, ...related.map(r => r.id)]);
  const addOptions = casesRegistry
    .filter(rc => !linkedIds.has(rc.id))
    .map(rc => `<option value="${rc.id}">${rc.id} · ${escapeHtml(rc.crimeType)} · ${escapeHtml(rc.region)}</option>`)
    .join('');

  const editBlock = canEdit
    ? `<div class="related-cases-edit">
        <p class="muted related-cases-edit-hint">Вы — руководитель дела · можно добавлять и удалять связи</p>
        <div class="related-cases-add">
          <select id="related-case-add-select" class="related-case-add-select">
            <option value="">Выберите дело…</option>
            ${addOptions}
          </select>
          <input type="text" id="related-case-add-link" class="related-case-add-link" placeholder="Тип связи (напр. связь по счёту)" value="связь по материалам">
          <button type="button" class="btn-sm" onclick="addRelatedCaseLink('${c.id}')">Добавить связь</button>
        </div>
      </div>`
    : `<p class="muted related-cases-readonly-hint">Только просмотр · изменять связи могут руководители дела: ${escapeHtml(getCaseManagersDisplay(c.id).join(', ') || c.lead || '—')}</p>`;

  return `
    <h2 style="margin-top:1.5rem">Похожие дела</h2>
    <ul class="related-cases">${itemsHtml}</ul>
    ${editBlock}
  `;
}

function caseGraphSlug(caseId) {
  const m = (caseId || '').match(/(\d{4,6})$/);
  return m ? m[1] : (caseId || '').replace(/\W/g, '').slice(-6) || '000000';
}

/** Краткое имя региона для карточек графа и узлов (не последнее слово «край»/«область»). */
const REGION_DISPLAY_SHORT = {
  'Краснодарский край': 'Краснодар',
  'Ставропольский край': 'Ставрополь',
  'Ростовская область': 'Ростов',
  'Республика Татарстан': 'Казань',
  'Москва': 'Москва',
  'Федеральный': 'Федеральный'
};

function formatRegionShort(region) {
  if (!region) return 'Дело';
  const trimmed = String(region).trim();
  if (REGION_DISPLAY_SHORT[trimmed]) return REGION_DISPLAY_SHORT[trimmed];
  const krai = trimmed.match(/^(.+?)ский\s+край$/iu);
  if (krai) return krai[1];
  const obl = trimmed.match(/^(.+?)ская\s+область$/iu);
  if (obl) return obl[1];
  const rep = trimmed.match(/^Республика\s+(.+)$/iu);
  if (rep) return rep[1];
  const ao = trimmed.match(/^(.+?)\s+АО$/iu);
  if (ao) return ao[1];
  if (!trimmed.includes(' ')) return trimmed;
  return trimmed.split(/\s+/)[0];
}

function getCaseRegionShort(caseId) {
  return formatRegionShort(getCaseById(caseId)?.region);
}

function syncGraphCaseAnchorShorts() {
  Object.keys(GRAPH_CASE_ANCHORS).forEach(caseId => {
    const short = getCaseRegionShort(caseId);
    if (short) GRAPH_CASE_ANCHORS[caseId].short = short;
  });
  graphNodes.forEach(n => {
    if (n.type !== 'case' || !n.caseId) return;
    const anchor = GRAPH_CASE_ANCHORS[n.caseId];
    if (anchor?.caseNodeId === n.id || /^cg-.+-case$/.test(n.id)) {
      n.label = getCaseRegionShort(n.caseId);
    }
  });
  graphNodes.forEach(n => {
    if (n.type === 'phone' && n.sourceValue) {
      n.label = formatPhoneRu(n.sourceValue);
    }
  });
}

function isOpenCase(c) {
  return c && c.status !== 'court';
}

function graphNodeExists(id) {
  return graphNodes.some(n => n.id === id);
}

function addGraphNodeIfNew(node) {
  if (graphNodeExists(node.id)) return false;
  graphNodes.push(node);
  return true;
}

function addGraphEdgeIfNew(a, b) {
  const key = [a, b].sort().join('|');
  if (graphEdges.some(e => [e[0], e[1]].sort().join('|') === key)) return;
  graphEdges.push([a, b]);
}

function createInitialCaseGraph(c) {
  const slug = caseGraphSlug(c.id);
  const caseNodeId = `cg-${slug}-case`;
  const anchorId = `cg-${slug}-lead`;
  const short = formatRegionShort(c.region);
  graphNodes.push(
    { id: caseNodeId, type: 'case', label: short, detail: `${c.id} · ${c.article} · ${c.stage}. Граф создан автоматически при возбуждении дела.`, caseId: c.id },
    { id: anchorId, type: 'person', label: 'Фигурант', detail: `Первичный контур ${c.id}. Узлы добавляются по ходу следствия и при импорте из открытых источников.`, caseId: c.id }
  );
  graphEdges.push([anchorId, caseNodeId]);
  GRAPH_CASE_ANCHORS[c.id] = { caseNodeId, anchorId, short };
}

function syncGraphFromCase(c) {
  if (!c) return;
  const slug = caseGraphSlug(c.id);
  const anchor = GRAPH_CASE_ANCHORS[c.id]?.anchorId || `cg-${slug}-lead`;
  (c.team || []).slice(0, 4).forEach((m, i) => {
    const id = `cg-${slug}-tm-${i}`;
    if (addGraphNodeIfNew({ id, type: 'person', label: m.name.split(' ')[0], detail: `${m.name} — ${m.role}`, caseId: c.id })) {
      addGraphEdgeIfNew(anchor, id);
    }
  });
  (c.timeline || []).forEach((t, i) => {
    if (t.osint) {
      const id = `cg-${slug}-ph-osint`;
      if (addGraphNodeIfNew({ id, type: 'phone', label: formatPhoneRu(t.text.match(/\+?\d[\d\s()-]{8,}/)?.[0] || '') || '+7 (900) 000-00-00', detail: t.text, caseId: c.id, sourceKey: `phone:${slug}`, sourceValue: '' })) {
        addGraphEdgeIfNew(anchor, id);
      }
    }
    if (/счёт|РФМ|банк|перевод/i.test(t.text)) {
      const id = `cg-${slug}-acc`;
      if (addGraphNodeIfNew({ id, type: 'account', label: 'Счёт ***', detail: t.text, caseId: c.id })) {
        addGraphEdgeIfNew(anchor, id);
      }
    }
    if (/обыск|изъят/i.test(t.text)) {
      const id = `cg-${slug}-dev-${i}`;
      if (addGraphNodeIfNew({ id, type: 'org', label: 'Носитель', detail: t.text, caseId: c.id })) {
        addGraphEdgeIfNew(anchor, id);
      }
    }
  });
  (c.related || []).forEach((r, i) => {
    ensureCaseGraph(r.id);
    const relCaseNode = GRAPH_CASE_ANCHORS[r.id]?.caseNodeId;
    const id = `cg-${slug}-rel-${i}`;
    if (addGraphNodeIfNew({ id, type: 'case', label: r.place, detail: `${r.id} · ${r.link}`, caseId: c.id })) {
      addGraphEdgeIfNew(anchor, id);
      if (relCaseNode) addGraphEdgeIfNew(id, relCaseNode);
    }
  });
}

const graphSyncInProgress = new Set();

function ensureCaseGraph(caseId) {
  const c = getCaseById(caseId);
  if (!c) return;
  if (graphSyncInProgress.has(caseId)) return;
  graphSyncInProgress.add(caseId);
  try {
    if (!graphNodes.some(n => n.caseId === caseId)) createInitialCaseGraph(c);
    syncGraphFromCase(c);
  } finally {
    graphSyncInProgress.delete(caseId);
  }
}

function bootstrapAllCaseGraphs() {
  casesRegistry.filter(isOpenCase).forEach(c => ensureCaseGraph(c.id));
  syncGraphCaseAnchorShorts();
}

function appendCaseTimelineEntry(caseId, text, opts = {}) {
  const c = getCaseById(caseId);
  if (!c) return;
  c.timeline = c.timeline || [];
  c.timeline.push({ date: '14.06.2028', text, ...opts });
  syncGraphFromCase(c);
  if (activeCaseId === caseId) renderCaseDetail(caseId);
  if (activeGraphCaseId === caseId) graphView.afterDataChange?.();
}

let demoCaseSeq = 99100;

function canCreateCase() {
  const rt = getActivePersona().roleType;
  return rt === 'inv' || rt === 'inv_lead' || rt === 'ops';
}

function openNewCaseModal() {
  if (!canCreateCase()) {
    showToast('Создание дела доступно следователю и дознавателю.');
    return;
  }
  const p = getActivePersona();
  const scope = p.caseScope || {};
  document.getElementById('new-case-region').value = scope.region || '';
  document.getElementById('new-case-department').value = scope.department || p.department || '';
  document.getElementById('new-case-agency').value = scope.agency || p.agency || 'МВД';
  document.getElementById('new-case-crime').value = '';
  document.getElementById('new-case-article').value = '159.3 УК РФ';
  document.getElementById('new-case-modal')?.classList.remove('hidden');
}

function closeNewCaseModal() {
  document.getElementById('new-case-modal')?.classList.add('hidden');
}

function submitNewCase(e) {
  e.preventDefault();
  if (!canCreateCase()) return;
  const p = getActivePersona();
  const crimeType = document.getElementById('new-case-crime')?.value.trim();
  const article = document.getElementById('new-case-article')?.value.trim() || '159.3 УК РФ';
  const region = document.getElementById('new-case-region')?.value.trim() || p.region || 'Краснодарский край';
  const department = document.getElementById('new-case-department')?.value.trim() || p.department || 'СО №3';
  const agencyCode = document.getElementById('new-case-agency')?.value || 'МВД';
  const agencyNames = { MVD: 'МВД России', SK: 'СК РФ', FSB: 'ФСБ России' };
  if (!crimeType) { showToast('Укажите краткое описание состава преступления.'); return; }
  demoCaseSeq += 1;
  const id = `ЕПСОК-2028-${String(demoCaseSeq).slice(-6)}`;
  const newCase = {
    id,
    region,
    department,
    agency: agencyCode,
    agencyName: agencyNames[agencyCode] || agencyCode,
    article,
    crimeType,
    status: 'investigating',
    stage: 'Следствие',
    lead: p.name,
    managers: [p.id],
    opened: '14.06.2028',
    daysLeft: 60,
    timeline: [{ date: '14.06.2028', text: 'Возбуждено уголовное дело · граф связей создан автоматически', highlight: true }],
    team: [{ name: p.name, role: 'следователь (ответственный)' }],
    related: []
  };
  casesRegistry.unshift(newCase);
  ensureCaseGraph(id);
  closeNewCaseModal();
  activeCaseId = id;
  showToast(`${id} зарегистрировано · граф связей инициализирован`);
  renderCasesRegistry();
  showView('case');
}

function renderCasePickerHtml(selectedId) {
  const cases = getPersonaScopedCases();
  if (cases.length <= 1) return '';
  return `<label class="field case-picker-field">
    <span>Дело</span>
    <select id="case-detail-picker" onchange="openCase(this.value)">
      ${cases.map(c => `<option value="${c.id}" ${c.id === selectedId ? 'selected' : ''}>${c.id} · ${escapeHtml(c.article)} · ${escapeHtml(c.crimeType)}</option>`).join('')}
    </select>
  </label>`;
}

let activeDeadlinesCaseId = null;

function getCaseDeadlines(caseId) {
  const c = getCaseById(caseId);
  if (!c) return [];
  const dl = c.daysLeft;
  const pct = dl != null ? Math.min(98, Math.max(5, 100 - dl * 1.5)) : 0;
  const level = dl != null && dl <= 3 ? 'critical' : dl != null && dl <= 7 ? 'warning' : 'ok';
  const items = [];
  if (c.status === 'suspended') {
    items.push({ type: 'Приостановление', article: 'ст. 208 УПК РФ', limit: 'до 3 месяцев', expires: '—', daysLeft: null, pct: 0, level: 'paused', info: 'Таймеры приостановлены · розыск фигуранта' });
  } else if (c.stage === 'Дознание') {
    items.push({ type: 'Дознание', article: 'ст. 223 УПК РФ', limit: '30 суток (+30)', expires: dl != null ? `+${dl} дн.` : '—', daysLeft: dl, pct, level, action: dl != null && dl <= 7 ? 'Контроль продления дознания' : null });
  } else {
    items.push({ type: 'Предварительное следствие', article: 'ст. 162 УПК РФ', limit: '2 месяца (+3–6 мес.)', expires: dl != null ? `осталось ${dl} дн.` : '—', daysLeft: dl, pct, level, action: dl != null && dl <= 7 ? '⚠ Требуется ходатайство о продлении' : null });
  }
  items.push({ type: 'Задержание (если применялось)', article: 'ст. 109 УПК РФ', limit: '48 ч → 72 ч', expires: 'не применялось', daysLeft: null, pct: 0, level: 'ok', info: 'В деле нет активного задержания' });
  items.push({ type: 'Экспертиза', article: 'ст. 195–207 УПК РФ', limit: 'по виду экспертизы', expires: dl != null ? `~${dl + 12} дн.` : '—', daysLeft: dl != null ? dl + 12 : null, pct: Math.max(15, 100 - pct), level: 'ok', info: 'Компьютерная экспертиза · очередь ЦОД' });
  items.push({ type: 'Ознакомление с материалами', article: 'ст. 217 УПК РФ', limit: '5 суток', expires: 'не назначено', daysLeft: null, pct: 0, level: 'paused', info: 'После окончания следственных действий' });
  if (c.cluster) {
    items.push({ type: 'Межведомственные запросы', article: 'ПОЛ-003 · SLA', limit: '4 ч – 3 раб. дня', expires: 'активные: 2', daysLeft: 4, pct: 55, level: 'ok', info: `Кластер ${c.cluster} · РФМ, ФНС` });
  }
  return items;
}

function renderDeadlines() {
  const root = document.getElementById('deadlines-root');
  if (!root) return;
  const cases = getPersonaScopedCases().filter(isOpenCase);
  if (!activeDeadlinesCaseId || !cases.some(c => c.id === activeDeadlinesCaseId)) {
    activeDeadlinesCaseId = activeCaseId && cases.some(c => c.id === activeCaseId) ? activeCaseId : cases[0]?.id;
  }
  const c = getCaseById(activeDeadlinesCaseId);
  if (!c) {
    root.innerHTML = '<div class="panel"><p class="muted">Нет дел для контроля сроков в вашем контуре.</p></div>';
    return;
  }
  const cards = getCaseDeadlines(c.id).map(d => `
    <div class="deadline-card ${d.level}">
      <div class="dl-type">${escapeHtml(d.type)}</div>
      <div class="dl-article">${escapeHtml(d.article)}${d.limit ? ` · ${escapeHtml(d.limit)}` : ''}</div>
      <div class="dl-bar"><div class="dl-fill ${d.level === 'ok' ? 'ok' : ''}" style="width:${d.pct || 0}%"></div></div>
      <div class="dl-info">${d.daysLeft != null ? `Осталось <strong>${d.daysLeft} дн.</strong>` : escapeHtml(d.expires)}${d.info ? ` · ${escapeHtml(d.info)}` : ''}</div>
      ${d.action ? `<div class="dl-action">${escapeHtml(d.action)}</div>` : ''}
    </div>`).join('');
  root.innerHTML = `
    <div class="deadlines-toolbar panel">
      <label class="field case-picker-field">
        <span>Дело</span>
        <select id="deadlines-case-picker" onchange="selectDeadlinesCase(this.value)">
          ${cases.map(x => `<option value="${x.id}" ${x.id === c.id ? 'selected' : ''}>${x.id} · ${escapeHtml(x.article)}</option>`).join('')}
        </select>
      </label>
      <div class="deadlines-summary">
        <span class="badge ${c.status}">${caseStatusLabels[c.status]}</span>
        <span class="muted">${escapeHtml(c.lead)} · ${escapeHtml(c.opened)}</span>
        ${c.daysLeft != null ? `<span class="cases-deadline ${c.daysLeft <= 3 ? 'critical' : c.daysLeft <= 7 ? 'warning' : ''}">${c.daysLeft} дн. до ключевого срока</span>` : ''}
      </div>
      <button type="button" class="btn-sm" onclick="openCase('${c.id}')">Карточка дела</button>
      ${canAccessView('graph') ? `<button type="button" class="btn-sm" onclick="openCaseGraph('${c.id}')">Граф связей</button>` : ''}
      ${canAccessView('horizon') ? `<button type="button" class="btn-sm" onclick="selectHorizonCase('${c.id}');showView('horizon')">Горизонт</button>` : ''}
    </div>
    <div class="panel">
      <h2>Контроль процессуальных сроков · ${c.id}</h2>
      <p class="muted deadlines-hint">${escapeHtml(c.article)} · ${escapeHtml(c.region)} · ${escapeHtml(c.department)}</p>
      <div class="deadline-cards">${cards}</div>
      <div class="deadlines-foot muted">Источник: реестр дел ЕПСОК · пересчёт при изменении этапа · уведомления в журнал аудита</div>
    </div>`;
}

function selectDeadlinesCase(caseId) {
  activeDeadlinesCaseId = caseId;
  activeCaseId = caseId;
  renderDeadlines();
  updateHeaderContext();
}

function getPersonaScopedCases() {
  const scope = getActivePersona().caseScope;
  if (!scope) return casesRegistry.slice();
  return casesRegistry.filter(c => {
    if (scope.agency && c.agency !== scope.agency) return false;
    if (scope.region && c.region !== scope.region) return false;
    if (scope.department && c.department !== scope.department) return false;
    return true;
  });
}

function getPersonaFilterLocks() {
  const scope = getActivePersona().caseScope;
  if (!scope) return { region: false, department: false, agency: false };
  return {
    region: !!scope.region,
    department: !!scope.department,
    agency: !!scope.agency
  };
}

function getCaseFilterDepartments(region, agency) {
  const pool = getPersonaScopedCases().filter(c => {
    if (c.region !== region) return false;
    if (agency && !isCasesFilterAll(agency) && c.agency !== agency) return false;
    return true;
  });
  return [...new Set(pool.map(c => c.department))].sort();
}

function getCasesCascadeOptions(region, agency) {
  const scope = getActivePersona().caseScope;
  let base = casesRegistry.slice();
  if (scope) {
    base = base.filter(c => {
      if (scope.agency && c.agency !== scope.agency) return false;
      if (scope.region && c.region !== scope.region) return false;
      return true;
    });
  }
  const regions = [...new Set(base.map(c => c.region))].sort();
  const agencies = region ? getCaseFilterAgencies(region) : [];
  const departments = region && agency ? getCaseFilterDepartments(region, agency) : [];
  return { regions, agencies, departments };
}

function getFilteredCases() {
  const region = document.getElementById('cases-filter-region')?.value || '';
  const agency = document.getElementById('cases-filter-agency')?.value || '';
  const department = document.getElementById('cases-filter-department')?.value || '';
  if (!region || !agency || !department) return [];

  let pool = getPersonaScopedCases().filter(c => c.region === region);
  if (!isCasesFilterAll(agency)) pool = pool.filter(c => c.agency === agency);
  if (!isCasesFilterAll(department)) pool = pool.filter(c => c.department === department);
  return pool;
}

function formatCasesCount(n) {
  const mod10 = n % 10;
  const mod100 = n % 100;
  if (mod100 >= 11 && mod100 <= 14) return `${n} дел`;
  if (mod10 === 1) return `${n} дело`;
  if (mod10 >= 2 && mod10 <= 4) return `${n} дела`;
  return `${n} дел`;
}

function resolveAgencySelection(savedAgency, agencies, locks) {
  const defaults = getPersonaDefaultFilters();
  if (savedAgency === CASES_FILTER_ALL && !locks.agency) return CASES_FILTER_ALL;
  if (savedAgency && agencies.some(a => a.code === savedAgency)) return savedAgency;
  if (locks.agency && defaults.agency) return defaults.agency;
  if (defaults.agency && agencies.some(a => a.code === defaults.agency)) return defaults.agency;
  const withCases = agencies.filter(a => a.count > 0);
  if (withCases.length === 1) return withCases[0].code;
  return '';
}

function updateCasesBreadcrumb(region, agency, department) {
  const el = document.getElementById('cases-breadcrumb');
  if (!el) return;
  const crumbs = [];
  if (region) crumbs.push(`<span class="cases-crumb">${escapeHtml(region)}</span>`);
  else crumbs.push('<span class="cases-crumb muted-crumb">регион не выбран</span>');
  if (agency) {
    crumbs.push(`<span class="cases-crumb">${escapeHtml(formatAgencyFilterLabel(agency))}</span>`);
  } else if (region) {
    crumbs.push('<span class="cases-crumb muted-crumb">ведомство не выбрано</span>');
  }
  if (department) {
    crumbs.push(`<span class="cases-crumb">${escapeHtml(formatDepartmentFilterLabel(department))}</span>`);
  } else if (agency) {
    crumbs.push('<span class="cases-crumb muted-crumb">отдел не выбран</span>');
  }
  el.innerHTML = crumbs.join('');
}

function resolveFilterValue(saved, options, lock, scopeValue) {
  if (saved === CASES_FILTER_ALL && !lock) return CASES_FILTER_ALL;
  if (saved && options.includes(saved)) return saved;
  if (lock && scopeValue && options.includes(scopeValue)) return scopeValue;
  if (options.length === 1) return options[0];
  return '';
}

function updateCasesFilterUI() {
  const regionSel = document.getElementById('cases-filter-region');
  const deptSel = document.getElementById('cases-filter-department');
  const agencySel = document.getElementById('cases-filter-agency');
  const deptWrap = document.getElementById('cases-filter-department-wrap');
  const agencyWrap = document.getElementById('cases-filter-agency-wrap');
  const hint = document.getElementById('cases-filter-hint');
  if (!regionSel || !deptSel || !agencySel) return;

  const scope = getActivePersona().caseScope || {};
  const defaults = getPersonaDefaultFilters();
  const locks = getPersonaFilterLocks();
  let savedRegion = regionSel.value || defaults.region || '';
  let savedAgency = agencySel.value || defaults.agency || '';
  let savedDepartment = deptSel.value || defaults.department || '';
  const { regions, agencies, departments } = getCasesCascadeOptions(savedRegion, savedAgency);

  regionSel.innerHTML = '<option value="">Выберите регион</option>' +
    regions.map(r => `<option value="${escapeHtml(r)}">${escapeHtml(r)}</option>`).join('');
  regionSel.value = resolveFilterValue(savedRegion, regions, locks.region, defaults.region);
  regionSel.disabled = false;
  regionSel.classList.toggle('cases-filter-locked', locks.region);

  const showAgency = !!regionSel.value;
  agencyWrap?.classList.toggle('hidden', !showAgency);
  if (showAgency) {
    const agencyAllOpt = locks.agency
      ? '<option value="">Выберите ведомство</option>'
      : `<option value="${CASES_FILTER_ALL}">Все ведомства</option>`;
    agencySel.innerHTML = agencyAllOpt +
      agencies.map(a => {
        const suffix = a.count ? ` (${formatCasesCount(a.count)})` : '';
        return `<option value="${escapeHtml(a.code)}">${escapeHtml(a.name)}${suffix}</option>`;
      }).join('');
    agencySel.value = resolveAgencySelection(savedAgency, agencies, locks);
    agencySel.disabled = false;
    agencySel.classList.toggle('cases-filter-locked', locks.agency);
  } else {
    agencySel.value = '';
    agencySel.disabled = true;
    agencySel.classList.remove('cases-filter-locked');
  }

  const showDept = !!regionSel.value && !!agencySel.value;
  deptWrap?.classList.toggle('hidden', !showDept);
  if (showDept) {
    const deptAllOpt = locks.department ? '' : `<option value="${CASES_FILTER_ALL}">Все отделы</option>`;
    deptSel.innerHTML = '<option value="">Выберите отдел</option>' + deptAllOpt +
      departments.map(d => `<option value="${escapeHtml(d)}">${escapeHtml(d)}</option>`).join('');
    deptSel.value = resolveFilterValue(savedDepartment, departments, locks.department, defaults.department);
    if (!deptSel.value && !locks.department && departments.length) {
      deptSel.value = defaults.department && departments.includes(defaults.department)
        ? defaults.department
        : CASES_FILTER_ALL;
    }
    deptSel.disabled = false;
    deptSel.classList.toggle('cases-filter-locked', locks.department);
  } else {
    deptSel.value = '';
    deptSel.disabled = true;
    deptSel.classList.remove('cases-filter-locked');
  }

  document.querySelectorAll('.cases-step').forEach(el => {
    const step = el.dataset.step;
    const done = (step === 'region' && !!regionSel.value) ||
      (step === 'agency' && !!agencySel.value) ||
      (step === 'department' && !!deptSel.value);
    el.classList.toggle('active',
      (step === 'region' && !regionSel.value) ||
      (step === 'agency' && regionSel.value && !agencySel.value) ||
      (step === 'department' && regionSel.value && agencySel.value && !deptSel.value)
    );
    el.classList.toggle('done', done);
  });

  updateCasesBreadcrumb(regionSel.value, agencySel.value, deptSel.value);

  [regionSel, agencySel, deptSel].forEach(sel => {
    const label = sel.options[sel.selectedIndex]?.text?.trim();
    sel.title = label && label !== 'Выберите регион' && !label.startsWith('Выберите') ? label : '';
  });

  if (hint) {
    if (!regionSel.value) {
      hint.textContent = regions.length
        ? `Шаг 1: выберите регион — доступно ${regions.length} в вашем охвате`
        : 'Шаг 1: нет доступных регионов для текущей роли';
    } else if (!agencySel.value) {
      const withCases = agencies.filter(a => a.count > 0).length;
      hint.textContent = `Шаг 2: ведомство в «${regionSel.value}» — ${withCases} с делами · можно «Все ведомства»`;
    } else if (!deptSel.value) {
      hint.textContent = `Шаг 3: отдел для «${formatAgencyFilterLabel(agencySel.value)}» — ${departments.length} вариант(ов) или «Все отделы»`;
    } else {
      hint.textContent = `Показаны дела: ${regionSel.value} · ${formatAgencyFilterLabel(agencySel.value)} · ${formatDepartmentFilterLabel(deptSel.value)}`;
    }
  }
}

function populateCasesFilterSelects() {
  updateCasesFilterUI();
}

function renderCasesRegistry() {
  tablePageRefresh.cases = renderCasesRegistry;
  populateCasesFilterSelects();
  const filtered = getFilteredCases();
  const scoped = getPersonaScopedCases();
  const scopedTotal = scoped.length;
  const body = document.getElementById('cases-table-body');
  const title = document.getElementById('cases-results-title');
  const pill = document.getElementById('cases-total-pill');
  const emptyState = document.getElementById('cases-empty-state');
  const tableWrap = document.querySelector('.cases-table-wrap');
  const region = document.getElementById('cases-filter-region')?.value || '';
  const agency = document.getElementById('cases-filter-agency')?.value || '';
  const department = document.getElementById('cases-filter-department')?.value || '';
  const urgent = scoped.filter(c => c.daysLeft != null && c.daysLeft <= 7).length;

  const kpiTotal = document.getElementById('cases-kpi-total');
  const kpiShown = document.getElementById('cases-kpi-shown');
  const kpiUrgent = document.getElementById('cases-kpi-urgent');
  if (kpiTotal) kpiTotal.textContent = String(scopedTotal);
  if (kpiShown) kpiShown.textContent = String(filtered.length);
  if (kpiUrgent) kpiUrgent.textContent = String(urgent);

  if (!body) return;

  const showEmpty = (msg, sub) => {
    if (tableWrap) tableWrap.classList.add('hidden');
    if (emptyState) {
      emptyState.classList.remove('hidden');
      const t = document.getElementById('cases-empty-title');
      const s = document.getElementById('cases-empty-text');
      if (t) t.textContent = msg;
      if (s) s.textContent = sub;
    }
    body.innerHTML = '';
  };

  const showTable = () => {
    if (tableWrap) tableWrap.classList.remove('hidden');
    emptyState?.classList.add('hidden');
  };

  if (!region) {
    if (title) title.textContent = 'Дела';
    if (pill) pill.textContent = formatCasesCount(0);
    mountTablePagination('cases-pagination', { total: 0, pageSize: TABLE_PAGE_SIZE, key: 'cases' });
    showEmpty('Выберите регион', 'Затем ведомство и отдел — таблица заполнится по шагам');
    return;
  }

  if (!agency) {
    if (title) title.textContent = `Дела · ${region}`;
    if (pill) pill.textContent = formatCasesCount(0);
    mountTablePagination('cases-pagination', { total: 0, pageSize: TABLE_PAGE_SIZE, key: 'cases' });
    showEmpty('Выберите ведомство', `В регионе «${region}» укажите ведомство-инициатор`);
    return;
  }

  if (!department) {
    if (title) title.textContent = `Дела · ${formatAgencyFilterLabel(agency)}`;
    if (pill) pill.textContent = formatCasesCount(0);
    mountTablePagination('cases-pagination', { total: 0, pageSize: TABLE_PAGE_SIZE, key: 'cases' });
    showEmpty('Выберите отдел', `Для «${formatAgencyFilterLabel(agency)}» укажите следственный или оперативный отдел`);
    return;
  }

  if (title) title.textContent = filtered.length ? `Дела · ${region}` : `Дела · ${formatDepartmentFilterLabel(department)}`;
  if (pill) pill.textContent = formatCasesCount(filtered.length);

  if (filtered.length === 0) {
    const msg = !isCasesFilterAll(agency)
      ? `Нет дел: ${getAgencyDisplayName(agency)}`
      : 'Нет дел по фильтру';
    const sub = !isCasesFilterAll(department)
      ? 'Выберите другой отдел или «Все отделы»'
      : 'Выберите отдел или оставьте «Все отделы» для просмотра всех дел ведомства';
    mountTablePagination('cases-pagination', { total: 0, pageSize: TABLE_PAGE_SIZE, key: 'cases' });
    showEmpty(msg, sub);
    return;
  }

  showTable();
  const meta = paginateList(filtered, 'cases', measureTablePageSize(
    document.querySelector('#view-cases .table-scroll-paged')
  ));
  const showDeptCol = isCasesFilterAll(department);
  body.innerHTML = meta.slice.map(c => {
    const deadlineClass = c.daysLeft != null && c.daysLeft <= 3 ? 'critical' : c.daysLeft != null && c.daysLeft <= 7 ? 'warning' : '';
    const deadline = c.daysLeft != null ? `${c.daysLeft} дн.` : '—';
    const metaSub = showDeptCol
      ? `${escapeHtml(c.department)} · ${escapeHtml(c.region)}`
      : escapeHtml(c.region);
    return `<tr>
      <td class="case-id-cell">
        <button type="button" class="case-link" onclick="openCase('${c.id}')">${c.id}</button>
        <span class="case-meta-sub">${metaSub}</span>
      </td>
      <td>${escapeHtml(c.article.replace(' УК РФ', ''))}</td>
      <td><span class="badge ${c.status}">${caseStatusLabels[c.status]}</span><span class="case-meta-sub">${escapeHtml(c.stage)}</span></td>
      <td>${escapeHtml(c.agencyName)}</td>
      <td>${escapeHtml(getCaseManagersDisplay(c.id).join(', ') || c.lead)}</td>
      <td><span class="cases-deadline ${deadlineClass}">${deadline}</span></td>
      <td><button type="button" class="btn-sm cases-open-btn" onclick="openCase('${c.id}')">Открыть</button></td>
    </tr>`;
  }).join('');
  mountTablePagination('cases-pagination', meta);
}

function applyCasesFilters() {
  resetTablePage('cases');
  renderCasesRegistry();
}

function onCasesFilterRegionChange() {
  resetTablePage('cases');
  const locks = getPersonaFilterLocks();
  if (locks.region) {
    applyPersonaCaseDefaults();
    renderCasesRegistry();
    return;
  }
  const deptSel = document.getElementById('cases-filter-department');
  const agencySel = document.getElementById('cases-filter-agency');
  if (agencySel) agencySel.value = '';
  if (deptSel) deptSel.value = '';
  renderCasesRegistry();
}

function onCasesFilterAgencyChange() {
  resetTablePage('cases');
  const locks = getPersonaFilterLocks();
  if (locks.agency) {
    applyPersonaCaseDefaults();
    renderCasesRegistry();
    return;
  }
  const deptSel = document.getElementById('cases-filter-department');
  if (deptSel) deptSel.value = '';
  renderCasesRegistry();
}

function onCasesFilterDepartmentChange() {
  resetTablePage('cases');
  const locks = getPersonaFilterLocks();
  if (locks.department) {
    applyPersonaCaseDefaults();
    renderCasesRegistry();
    return;
  }
  renderCasesRegistry();
}

function resetCasesFilters() {
  resetTablePage('cases');
  const regionSel = document.getElementById('cases-filter-region');
  const deptSel = document.getElementById('cases-filter-department');
  const agencySel = document.getElementById('cases-filter-agency');
  const locks = getPersonaFilterLocks();
  if (regionSel && !locks.region) regionSel.value = '';
  if (deptSel && !locks.department) deptSel.value = '';
  if (agencySel && !locks.agency) agencySel.value = '';
  applyPersonaCaseDefaults();
  renderCasesRegistry();
}

function openCase(caseId) {
  if (!getCaseById(caseId)) {
    showToast('Дело не найдено в реестре.');
    return;
  }
  const inScope = personaCanAccessCase(caseId);
  if (!inScope && !getActivePersona().allowedViews.includes('case')) {
    showToast('ПОЛ-001: нет доступа к этому делу для текущей роли.');
    return;
  }
  if (!inScope) showToast('Только просмотр · вы не в составе дела');
  activeCaseId = caseId;
  activeDeadlinesCaseId = caseId;
  if (getCaseById(caseId)?.cluster || getCaseById(caseId)?.related?.length) activeHorizonCaseId = caseId;
  updateHeaderContext();
  showView('case');
}

function renderCaseDetail(caseId) {
  const root = document.getElementById('case-detail-root');
  const c = getCaseById(caseId);
  if (!root || !c) {
    if (root) root.innerHTML = '<p class="muted">Дело не выбрано. Перейдите в <button type="button" class="case-link" onclick="showView(\'cases\')">реестр дел</button>.</p>';
    return;
  }

  const timelineHtml = (c.timeline || []).map(t => `
    <div class="timeline-item ${t.highlight ? 'highlight' : ''}">
      <span class="tl-date">${t.date}</span>
      <span>${escapeHtml(t.text)}${t.osint && canRunOsint() ? ' <button class="btn-sm inline" onclick="showView(\'osint\')">Открыть</button>' : ''}</span>
    </div>
  `).join('');

  const teamHtml = (c.team || []).map(m =>
    `<li><strong>${escapeHtml(m.name)}</strong> — ${escapeHtml(m.role)}</li>`
  ).join('');

  const managersLabel = getCaseManagersDisplay(c.id);
  const managersHtml = managersLabel.length > 1
    ? `Руководители дела: ${escapeHtml(managersLabel.join(', '))}`
    : managersLabel.length === 1
      ? `Ответственный: ${escapeHtml(managersLabel[0])}`
      : `Ответственный: ${escapeHtml(c.lead)}`;

  root.innerHTML = `
    ${(() => {
      const ro = isCaseReadOnly(getActivePersona(), caseId);
      if (!ro) return '';
      const msg = !personaCanAccessCase(caseId)
        ? 'Только просмотр · вы не в составе дела (ПОЛ-001)'
        : 'Надзорный / аналитический контур · только просмотр (ПОЛ-002)';
      return `<p class="case-readonly-hint muted">${msg}</p>`;
    })()}
    <div class="case-header-bar">
      <div class="case-header-main">
        <span class="case-id">${c.id}</span>
        <span class="badge ${c.status}">${caseStatusLabels[c.status]}</span>
        ${c.cluster ? `<span class="link-badge">${c.cluster}</span>` : ''}
        <span class="link-badge">${countGraphNodesForCase(c.id)} узлов в графе</span>
      </div>
      ${renderCasePickerHtml(caseId)}
      <div class="case-meta">
        <span>${escapeHtml(c.article)} · ${escapeHtml(c.crimeType)}</span>
        <span>${escapeHtml(c.agencyName)} · ${escapeHtml(c.region)}</span>
        <span>${escapeHtml(c.department)}</span>
        <span>${managersHtml} · возбуждено ${escapeHtml(c.opened)}</span>
        ${c.daysLeft != null ? `<span class="cases-deadline ${c.daysLeft <= 7 ? 'warning' : ''}">Срок: ${c.daysLeft} дн.</span>` : ''}
      </div>
    </div>
    <div class="grid-2">
      <div class="panel">
        <h2>Хронология</h2>
        <div class="timeline">${timelineHtml || '<p class="muted">Нет записей</p>'}</div>
      </div>
      <div class="panel">
        <h2>Рабочая группа</h2>
        <ul class="team-list">${teamHtml}</ul>
        ${renderRelatedCasesSection(c)}
        <button type="button" class="btn-sm" style="margin-top:1rem" onclick="showView('cases')">← К реестру</button>
      </div>
    </div>
    ${renderCaseQuickLinksHtml(c)}
  `;
}

// --- Agencies (FZ-based functions) ---

let activeAgencyId = 'MVD';

const AGENCY_ROLE_POLICY = {
  inv: { mode: 'initiator', hidden: ['MINDIG'], canCreate: true },
  inv_lead: { mode: 'initiator', hidden: ['MINDIG'], canCreate: true },
  ops: { mode: 'initiator', hidden: ['MINDIG'], canCreate: true },
  prosecutor: { mode: 'readonly', hidden: ['MINDIG', 'FSB'], canCreate: false },
  prosecutor_mil: { mode: 'readonly', hidden: ['MINDIG', 'FSB'], canCreate: false },
  executor: { mode: 'own', hidden: ['MINDIG'], canCreate: false },
  analyst: { mode: 'readonly', hidden: ['MINDIG', 'FSB'], canCreate: false },
  court: { mode: 'readonly', visible: ['COURT', 'PROSECUTOR', 'FNS', 'FSSP', 'MVD'], canCreate: false },
  admin: { mode: 'none', canCreate: false },
  func_admin: { mode: 'none', canCreate: false }
};

const EXEC_AGENCY_IDS = {
  'МВД (ГИАЦ)': 'MVD',
  'ФНС': 'FNS',
  'ФСИН': 'FSIN',
  'ФТС': 'FTS',
  'ФССП': 'FSSP',
  'Росфинмониторинг': 'RFM',
  'Росреестр': 'ROSREESTR',
  'ЦБ': 'CBR'
};

function getAgencyPolicy(p) {
  return AGENCY_ROLE_POLICY[p.roleType] || AGENCY_ROLE_POLICY.inv;
}

function getExecutorAgencyId(p) {
  return EXEC_AGENCY_IDS[p.execAgency] || personaAgencyKey[p.agency] || null;
}

function isAgencySensitiveForPersona(agency, p) {
  return agency.sensitive && getPersonaAgencyKey(p) !== agency.id;
}

function getVisibleAgencies(p) {
  const policy = getAgencyPolicy(p);
  if (policy.mode === 'none') return [];
  let list = agencyRegistry.filter(a => !policy.hidden?.includes(a.id));
  if (policy.mode === 'own') {
    const ownId = getExecutorAgencyId(p);
    list = ownId ? list.filter(a => a.id === ownId) : [];
  } else if (policy.visible?.length) {
    list = list.filter(a => policy.visible.includes(a.id));
  }
  return list;
}

function canCreateAgencyRequest(agency, p) {
  const policy = getAgencyPolicy(p);
  if (!policy.canCreate || isAgencySensitiveForPersona(agency, p)) return false;
  return (requestTypesByAgency[agency.id] || []).length > 0;
}

function ensureActiveAgencyVisible() {
  const visible = getVisibleAgencies(getActivePersona());
  if (!visible.length) return;
  if (!visible.some(a => a.id === activeAgencyId)) activeAgencyId = visible[0].id;
}

function getAgenciesContextText(p) {
  const policy = getAgencyPolicy(p);
  if (policy.mode === 'none') return 'Раздел недоступен для вашей роли';
  if (policy.mode === 'own') return `Ваш контур исполнителя · ${p.execAgency || p.group}`;
  if (policy.mode === 'readonly') return 'Справочный просмотр · создание запросов недоступно';
  return 'Куда направить межведомственный запрос · ПОЛ-003';
}

function renderAgencies() {
  const p = getActivePersona();
  const visible = getVisibleAgencies(p);
  ensureActiveAgencyVisible();

  const ctx = document.getElementById('agencies-context');
  if (ctx) ctx.textContent = getAgenciesContextText(p);

  const kpiCount = document.getElementById('agencies-kpi-count');
  const kpiReq = document.getElementById('agencies-kpi-req');
  if (kpiCount) kpiCount.textContent = String(visible.length);
  if (kpiReq) {
    const reqCount = visible.reduce((n, a) => n + (isAgencySensitiveForPersona(a, p) ? 0 : (requestTypesByAgency[a.id] || []).length), 0);
    kpiReq.textContent = String(reqCount);
  }

  renderAgenciesNav(visible);
  renderAgencyDetail(activeAgencyId);
}

function renderAgenciesNav(visible) {
  const nav = document.getElementById('agencies-nav');
  if (!nav) return;
  if (!visible.length) {
    nav.innerHTML = '<p class="muted agencies-nav-empty">Нет доступных ведомств</p>';
    return;
  }
  nav.innerHTML = visible.map(a => `
    <button type="button" class="agencies-nav-item ${activeAgencyId === a.id ? 'active' : ''}"
      style="--agency-color:${a.color}"
      onclick="selectAgency('${a.id}')">
      <span class="agencies-nav-dot" style="background:${a.color}"></span>
      <span class="agencies-nav-text">
        <span class="agencies-nav-name">${escapeHtml(a.name)}</span>
        <span class="agencies-nav-tag">${agencyCategoryLabels[a.category] || ''}</span>
      </span>
    </button>`).join('');
}

function selectAgency(id) {
  activeAgencyId = id;
  renderAgencies();
}

function renderAgencyDetail(id) {
  const el = document.getElementById('agency-detail');
  if (!el) return;
  const p = getActivePersona();
  const visible = getVisibleAgencies(p);
  if (!visible.length) {
    el.innerHTML = '<div class="panel agencies-empty"><p class="muted">Справочник ведомств недоступен для вашей роли.</p></div>';
    return;
  }
  const a = agencyRegistry.find(x => x.id === id) || visible[0];
  const sensitive = isAgencySensitiveForPersona(a, p);
  const reqs = sensitive ? [] : (requestTypesByAgency[a.id] || []);
  const canCreate = canCreateAgencyRequest(a, p);
  const policy = getAgencyPolicy(p);
  const tag = agencyCategoryLabels[a.category] || '';

  const reqBlock = reqs.length
    ? `<div class="agencies-req-block">
        <h3>Запросы</h3>
        <ul class="agencies-req-list">${reqs.map(r => `
          <li class="agencies-req-item">
            <div class="agencies-req-main">
              <span class="agencies-req-label">${escapeHtml(r.label)}</span>
              <span class="agencies-req-law">${escapeHtml(r.law)}</span>
            </div>
            ${canCreate ? `<button type="button" class="btn-xs approve" onclick="createRequestForAgency('${a.id}','${r.type}')">Создать</button>` : ''}
          </li>`).join('')}
        </ul>
      </div>`
    : `<p class="muted agencies-no-req">${sensitive
      ? 'Детали взаимодействия — только для контуров ФСБ и по согласованию.'
      : policy.mode === 'own'
        ? 'Входящие запросы исполняются в разделе «Запросы».'
        : 'Исходящие запросы к этому ведомству не предусмотрены.'}</p>`;

  const modeNote = policy.mode === 'readonly'
    ? '<p class="agencies-mode-note">Только просмотр · надзорный контур</p>'
    : policy.mode === 'own' && a.id === getExecutorAgencyId(p)
      ? '<p class="agencies-mode-note">Ваш контур исполнителя</p>'
      : '';

  el.innerHTML = `
    <div class="panel agencies-detail-panel">
      <div class="agencies-detail-head">
        <div>
          <h2>${escapeHtml(a.name)}</h2>
          <p class="muted agencies-detail-summary">${escapeHtml(a.summary)}</p>
        </div>
        <span class="agencies-detail-tag" style="background:${a.color}18;color:${a.color}">${tag}</span>
      </div>
      ${modeNote}
      <p class="agencies-detail-law"><span>Основание:</span> ${escapeHtml(a.law)}</p>
      ${reqBlock}
      ${canCreate ? '<button type="button" class="btn-primary agencies-create-btn" onclick="openNewRequestModal()">+ Новый запрос</button>' : ''}
    </div>`;
}

const agencyCategoryLabels = {
  investigative: 'Следствие',
  supervisory: 'Надзор',
  operative: 'Оперативный контур',
  law_enforcement: 'Правоохранение',
  penitentiary: 'УИС',
  customs: 'Таможня',
  bailiff: 'Приставы',
  executive: 'Исполнитель',
  judiciary: 'Суды',
  operator: 'Инфраструктура'
};

const agencyRegistry = [
  {
    id: 'MVD', caseCode: 'МВД', category: 'investigative', name: 'МВД России', color: '#3b82f6',
    law: '3-ФЗ «О полиции»',
    summary: 'Проверки по базам, розыск, транспорт, детализация связи',
    functions: ['Проверка по ГИАЦ', 'Розыск и ИБД', 'Детализация связи', 'КУСП']
  },
  {
    id: 'SK', caseCode: 'СК', category: 'investigative', name: 'СК России', color: '#6366f1',
    law: '403-ФЗ «О СК России»',
    summary: 'Смежные дела, экспертизы, подследственность',
    functions: ['Смежное дело', 'Судебная экспертиза', 'Подследственность']
  },
  {
    id: 'PROSECUTOR', caseCode: 'ПРОКУРАТУРА', category: 'supervisory', name: 'Прокуратура России', color: '#8b5cf6',
    law: '2202-1 «О прокуратуре»',
    summary: 'Надзор, контроль сроков, продление следствия',
    functions: ['Надзорный доступ', 'Контроль сроков', 'Продление сроков']
  },
  {
    id: 'MILPROSEC', caseCode: 'ВОЕНПРОК', category: 'supervisory', name: 'Военная прокуратура', color: '#7c3aed',
    law: '2202-1, ст. 57',
    summary: 'Надзор за действиями военнослужащих',
    functions: ['Надзор за ВС РФ', 'Согласование следственных действий', 'Подследственность']
  },
  {
    id: 'FSB', caseCode: 'ФСБ', category: 'operative', name: 'ФСБ России', color: '#64748b',
    law: '40-ФЗ «О ФСБ»',
    summary: 'ОРД, грифованные дела, контрразведка',
    functions: ['Запрос ОРД', 'Связка дел', 'Передача по ст. 89 УПК'],
    sensitive: true
  },
  {
    id: 'RGV', caseCode: 'РОСГВАРДИЯ', category: 'law_enforcement', name: 'Росгвардия', color: '#84cc16',
    law: '226-ФЗ',
    summary: 'Оружие, частная охрана, охрана объектов',
    functions: ['Разрешение на оружие', 'Учёт ЧОО', 'Охрана объекта']
  },
  {
    id: 'FSIN', caseCode: 'ФСИН', category: 'penitentiary', name: 'ФСИН России', color: '#78716c',
    law: '196-ФЗ «Об УИС»',
    summary: 'Место отбывания, УДО, содержание в СИЗО',
    functions: ['Место отбывания', 'УДО', 'Содержание в СИЗО']
  },
  {
    id: 'FTS', caseCode: 'ФТС', category: 'customs', name: 'ФТС России', color: '#06b6d4',
    law: '289-ФЗ «О таможенном регулировании»',
    summary: 'Декларации, контрагенты, контрабанда',
    functions: ['Таможенная декларация', 'Контрагент и маршрут', 'Код ТН ВЭД']
  },
  {
    id: 'FSSP', caseCode: 'ФССП', category: 'bailiff', name: 'ФССП России', color: '#dc2626',
    law: '229-ФЗ «Об исполнительном производстве»',
    summary: 'Исполнительные листы, арест, розыск должника',
    functions: ['Исполнительный лист', 'Арест имущества', 'Запрет на выезд']
  },
  {
    id: 'FNS', caseCode: 'ФНС', category: 'executive', name: 'ФНС России', color: '#10b981',
    law: '129-ФЗ, НК РФ',
    summary: 'ЕГРЮЛ, доходы, сведения о счетах',
    functions: ['Выписка ЕГРЮЛ', '2-НДФЛ', 'Сведения о счетах']
  },
  {
    id: 'RFM', caseCode: 'РФМ', category: 'executive', name: 'Росфинмониторинг', color: '#f59e0b',
    law: '115-ФЗ «О ПОД/ФТ»',
    summary: 'Движение средств, признаки отмывания',
    functions: ['Движение средств', 'Признаки ПОД/ФТ', 'Цепочка операций']
  },
  {
    id: 'ROSREESTR', caseCode: 'РОСРЕЕСТР', category: 'executive', name: 'Росреестр', color: '#0d9488',
    law: '218-ФЗ «О регистрации недвижимости»',
    summary: 'Выписки ЕГРН, обременения',
    functions: ['Выписка ЕГРН', 'История прав', 'Обременения']
  },
  {
    id: 'COURT', caseCode: 'СУД', category: 'judiciary', name: 'Суды России', color: '#ec4899',
    law: '118-ФЗ «О судах»',
    summary: 'Определения, пакеты доказательств',
    functions: ['Судебное определение', 'Пакет доказательств']
  },
  {
    id: 'CBR', caseCode: 'ЦБ', category: 'executive', name: 'Банк России', color: '#1d4ed8',
    law: '86-ФЗ «О ЦБ»',
    summary: 'Запросы через Росфинмониторинг',
    functions: ['Запрос через РФМ', 'Блокировка счетов']
  },
  {
    id: 'MINDIG', caseCode: 'МИНЦИФРЫ', category: 'operator', name: 'Минцифры России', color: '#0ea5e9',
    law: '210-ФЗ «Об организации СМЭВ»',
    summary: 'Маршрутизация межведомственного обмена',
    functions: ['Маршрутизация СМЭВ', 'ЕСИА']
  }
];

const CASE_FILTER_AGENCY_CATEGORIES = ['investigative', 'supervisory', 'operative', 'law_enforcement', 'penitentiary', 'customs', 'bailiff'];

function getAgencyByCaseCode(code) {
  return agencyRegistry.find(a => a.caseCode === code || a.id === code);
}

function getAgencyDisplayName(code) {
  return getAgencyByCaseCode(code)?.name || code;
}

function getCaseFilterAgencies(region, department) {
  const scope = getActivePersona().caseScope;
  const pool = region
    ? getPersonaScopedCases().filter(c => {
      if (c.region !== region) return false;
      if (department && !isCasesFilterAll(department) && c.department !== department) return false;
      return true;
    })
    : [];
  const caseCounts = new Map();
  pool.forEach(c => caseCounts.set(c.agency, (caseCounts.get(c.agency) || 0) + 1));

  return agencyRegistry
    .filter(a => CASE_FILTER_AGENCY_CATEGORIES.includes(a.category))
    .filter(a => !scope?.agency || scope.agency === a.caseCode)
    .map(a => ({
      code: a.caseCode,
      name: a.name,
      count: caseCounts.get(a.caseCode) || 0
    }));
}

const requestTypesByAgency = {
  MVD: [
    { type: 'MVD_PERSON_CHECK', label: 'Проверка по ГИАЦ', law: '3-ФЗ' },
    { type: 'MVD_WANTED', label: 'Розыск / ИБД', law: '3-ФЗ' },
    { type: 'MVD_VEHICLE', label: 'Транспорт / ГИБДД', law: '3-ФЗ' },
    { type: 'MVD_CDR', label: 'Детализация связи', law: 'ст. 186 УПК' }
  ],
  SK: [
    { type: 'SK_CASE_LINK', label: 'Смежное дело', law: '403-ФЗ' },
    { type: 'SK_EXPERTISE', label: 'Судебная экспертиза', law: 'ст. 195 УПК' },
    { type: 'SK_SUBORDINATION', label: 'Подследственность', law: 'ст. 151 УПК' }
  ],
  FNS: [
    { type: 'FNS_EGRUL', label: 'Выписка ЕГРЮЛ', law: '129-ФЗ' },
    { type: 'FNS_INCOME_2NDFL', label: '2-НДФЛ', law: 'НК ст. 102' },
    { type: 'FNS_ACCOUNT_INFO', label: 'Сведения о счетах', law: 'НК ст. 93' }
  ],
  RFM: [
    { type: 'RFM_TRANSACTIONS', label: 'Движение средств', law: '115-ФЗ' },
    { type: 'RFM_PODFT_ALERT', label: 'Признаки ПОД/ФТ', law: '115-ФЗ' }
  ],
  FTS: [
    { type: 'FTS_DECLARATION', label: 'Таможенная декларация', law: '289-ФЗ' },
    { type: 'FTS_CONSIGNOR', label: 'Контрагент / маршрут', law: '289-ФЗ' }
  ],
  FSIN: [
    { type: 'FSIN_CUSTODY', label: 'Место отбывания', law: '196-ФЗ' },
    { type: 'FSIN_PAROLE', label: 'УДО', law: '196-ФЗ' }
  ],
  RGV: [
    { type: 'RGV_WEAPON', label: 'Разрешение на оружие', law: '150-ФЗ' }
  ],
  FSB: [
    { type: 'FSB_ORD_QUERY', label: 'Запрос ОРД', law: '40-ФЗ' },
    { type: 'FSB_CASE_LINK', label: 'Связка дел (гриф)', law: '40-ФЗ' }
  ],
  FSSP: [
    { type: 'FSSP_ENFORCE', label: 'Исполнительный лист', law: '229-ФЗ' },
    { type: 'FSSP_ARREST', label: 'Арест имущества', law: '229-ФЗ' },
    { type: 'FSSP_TRAVEL_BAN', label: 'Запрет на выезд', law: '229-ФЗ' }
  ],
  MILPROSEC: [
    { type: 'MILPROSEC_SUPERVISION', label: 'Надзорное производство', law: '2202-1 ст. 57' },
    { type: 'MILPROSEC_SUBORDINATION', label: 'Подследственность ВС', law: 'УПК ст. 151' }
  ],
  ROSREESTR: [
    { type: 'ROSREESTR_EGRN', label: 'Выписка ЕГРН', law: '218-ФЗ' },
    { type: 'ROSREESTR_ENCUMBRANCE', label: 'Обременения', law: '218-ФЗ' }
  ],
  CBR: [
    { type: 'CBR_VIA_RFM', label: 'Запрос через РФМ', law: '115-ФЗ' }
  ],
  PROSECUTOR: [
    { type: 'PROSEC_EXTENSION', label: 'Продление сроков', law: 'ст. 226 УПК' }
  ],
  COURT: [
    { type: 'CRT_COURT_ORDER', label: 'Судебное определение', law: 'УПК' }
  ],
  MINDIG: []
};

const personaAgencyKey = {
  МВД: 'MVD', СК: 'SK', ФСБ: 'FSB', ФТС: 'FTS', РОСГВАРДИЯ: 'RGV',
  PROSECUTOR: 'PROSECUTOR', MILPROSEC: 'MILPROSEC'
};

const intraAgencyRequestTypes = {
  MVD: [
    { type: 'MVD_INT_GIAC', label: 'Проверка по ГИАЦ', law: '3-ФЗ', units: ['ГИАЦ · Краснодарский край', 'ГИАЦ · ЮФО', 'ГИАЦ · Москва'] },
    { type: 'MVD_INT_EXPERT', label: 'Назначение экспертизы', law: 'ст. 195 УПК', units: ['ЦЭК МВД · ЮФО', 'ЦЭК МВД · ЦФО'] },
    { type: 'MVD_INT_SO', label: 'Смежное СО', law: 'УПК', units: ['СО №1 · Прикубанский', 'СО №7 · Москва', 'СО №12 · Ростов'] }
  ],
  SK: [
    { type: 'SK_INT_EXPERT', label: 'Судебная экспертиза', law: 'ст. 195 УПК', units: ['Экспертное управление СК', 'СЭУ по ЮВАО'] },
    { type: 'SK_INT_SO', label: 'Смежное следственное управление', law: '403-ФЗ', units: ['СУ по СЗАО', 'СУ по ЮВАО', 'СУ по Краснодарскому краю'] }
  ],
  FSB: [
    { type: 'FSB_INT_ORD', label: 'Запрос в управление ОРД', law: '40-ФЗ', units: ['Управление контрразведки', 'Оперативно-аналитическое управление'] },
    { type: 'FSB_INT_CASE', label: 'Связка грифованных дел', law: '40-ФЗ', units: ['Следственный отдел УФСБ', 'УФСБ по соседнему региону'] }
  ],
  FTS: [
    { type: 'FTS_INT_SO', label: 'Смежное таможенное СО', law: '289-ФЗ', units: ['Таможня Домодедово', 'ЦТУ · Москва', 'Таможня Внуково'] },
    { type: 'FTS_INT_DECL', label: 'Внутр. запрос по декларации', law: '289-ФЗ', units: ['Центральное таможенное управление'] }
  ],
  RGV: [
    { type: 'RGV_INT_WEAPON', label: 'Сверка реестра оружия', law: '150-ФЗ', units: ['Лицензионно-разрешительный отдел', 'Управление по региону'] }
  ]
};

const intraDepartmentRequestTypes = {
  MVD: [
    { type: 'MVD_DEPT_OPS', label: 'Оперативная справка (ОУР)', law: 'УПК ст. 7', targets: ['ОУР №4 (прикреплён)', 'ОУР №2', 'Группа ОРМ'] },
    { type: 'MVD_DEPT_APPROVAL', label: 'Согласование следственного действия', law: 'УПК', targets: ['Руководитель СО', 'Зам. руководителя СО'] },
    { type: 'MVD_DEPT_TRANSFER', label: 'Передача материалов', law: 'УПК ст. 144', targets: ['Опергруппа СО', 'Дознаватель ГУ', 'Криминалист'] }
  ],
  SK: [
    { type: 'SK_DEPT_APPROVAL', label: 'Согласование следственного действия', law: 'УПК', targets: ['Руководитель СУ', 'Старший следователь СУ'] },
    { type: 'SK_DEPT_EXPERT', label: 'Поручение эксперту отдела', law: 'ст. 195 УПК', targets: ['Эксперт отдела', 'Специалист СУ'] }
  ],
  FSB: [
    { type: 'FSB_DEPT_APPROVAL', label: 'Согласование выезда / действия', law: '40-ФЗ', targets: ['Руководитель УФСБ', 'Начальник следственного отдела'] },
    { type: 'FSB_DEPT_OPS', label: 'Оперативное обеспечение', law: '144-ФЗ', targets: ['Опергруппа УФСБ', 'Группа контрразведки'] }
  ],
  FTS: [
    { type: 'FTS_DEPT_APPROVAL', label: 'Согласование проверки', law: '289-ФЗ', targets: ['Начальник таможни', 'Зам. начальника'] },
    { type: 'FTS_DEPT_TRANSFER', label: 'Передача материалов проверки', law: '289-ФЗ', targets: ['Группа досмотра', 'Таможенный инспектор'] }
  ],
  RGV: [
    { type: 'RGV_DEPT_OPS', label: 'Оперативное донесение', law: '226-ФЗ', targets: ['Опергруппа', 'Дежурная часть'] }
  ]
};

let requestFilterScope = 'all';
let requestSeq = 88512;

function getPersonaAgencyKey(p) {
  if (!p) return 'MVD';
  const fromAgency = personaAgencyKey[p.agency];
  if (fromAgency) return fromAgency;
  if (p.agency === 'МВД' || p.agency?.startsWith('MVD')) return 'MVD';
  return 'MVD';
}

function requestMatchesPersona(r, p) {
  if (p.dashboardMode === 'executor') {
    const exec = p.execAgency || '';
    if (r.scope === 'interagency') {
      return r.agency === exec || r.agency.startsWith(exec.split(' ')[0]) || r.target === exec;
    }
    if (r.scope === 'intra_agency') {
      return r.target.includes(exec) || (exec.includes('ГИАЦ') && r.type.includes('ГИАЦ'));
    }
    return false;
  }
  const agencyKey = getPersonaAgencyKey(p);
  const agencyName = p.agency;
  if (r.scope === 'interagency') return true;
  if (r.scope === 'intra_agency') return r.agency === agencyName || r.agency === agencyKey;
  if (r.scope === 'intra_department') {
    if (r.agency !== agencyName && r.agency !== agencyKey) return false;
    if (p.department && r.department) return r.department === p.department;
    return true;
  }
  return true;
}

function getFilteredRequests() {
  const p = getActivePersona();
  let rows = platformRequests.filter(r => requestMatchesPersona(r, p));
  if (requestFilterScope !== 'all') rows = rows.filter(r => r.scope === requestFilterScope);
  return rows;
}

function renderRequestScopeBadge(scope) {
  const s = REQUEST_SCOPES[scope] || REQUEST_SCOPES.interagency;
  return `<span class="req-scope-badge ${s.className}">${s.short}</span>`;
}

function renderRequests() {
  tablePageRefresh.requests = renderRequests;
  const tbody = document.getElementById('requests-table-body');
  const summary = document.getElementById('requests-summary');
  if (!tbody) return;
  const rows = getFilteredRequests();
  const p = getActivePersona();
  const personaRows = platformRequests.filter(r => requestMatchesPersona(r, p));
  const counts = { all: personaRows.length, interagency: 0, intra_agency: 0, intra_department: 0 };
  personaRows.forEach(r => { if (counts[r.scope] != null) counts[r.scope] += 1; });

  document.querySelectorAll('.req-scope-tab').forEach(btn => {
    const scope = btn.dataset.scope;
    const n = scope === 'all' ? counts.all : counts[scope];
    btn.classList.toggle('active', requestFilterScope === scope);
    const countEl = btn.querySelector('.req-tab-count');
    if (countEl) countEl.textContent = String(n ?? rows.length);
  });

  if (summary) {
    summary.textContent = p.dashboardMode === 'executor'
      ? `Очередь · ${p.execAgency || p.group}`
      : `${p.department || p.group} · ${counts.all} запрос(ов)`;
  }

  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="8" class="muted" style="text-align:center;padding:2rem">Нет запросов в выбранной категории</td></tr>`;
    mountTablePagination('requests-pagination', { total: 0, pageSize: TABLE_PAGE_SIZE, key: 'requests' });
    return;
  }

  const meta = paginateList(rows, 'requests', measureTablePageSize(
    document.querySelector('#view-requests .table-scroll-paged')
  ));
  tbody.innerHTML = meta.slice.map(r => `
    <tr>
      <td>${r.id}</td>
      <td>${renderRequestScopeBadge(r.scope)}</td>
      <td>${escapeHtml(r.type)}</td>
      <td>${escapeHtml(r.target)}</td>
      <td class="muted">${escapeHtml(r.from)}</td>
      <td><span class="status ${r.status}">${requestStatusLabels[r.status] || r.status}</span></td>
      <td>${r.sent}</td>
      <td>${r.sla}</td>
    </tr>`).join('');
  mountTablePagination('requests-pagination', meta);
}

function setRequestFilter(scope) {
  requestFilterScope = scope;
  resetTablePage('requests');
  renderRequests();
}

function createRequestForAgency(agencyId, type) {
  openNewRequestModal('interagency', agencyId, type);
}

function openNewRequestModal(presetScope, presetAgency, presetType) {
  if (!canCreateRequest()) {
    showToast('Создание запросов недоступно для вашей роли (ПОЛ-003).');
    return;
  }
  const modal = document.getElementById('request-modal');
  const scopeSel = document.getElementById('req-scope');
  const agencySel = document.getElementById('req-agency');
  const agencies = Object.keys(requestTypesByAgency).filter(k => requestTypesByAgency[k].length);
  if (agencySel) {
    agencySel.innerHTML = agencies.map(k => {
      const a = agencyRegistry.find(x => x.id === k);
      return `<option value="${k}">${a ? a.name : k}</option>`;
    }).join('');
    if (presetAgency && agencies.includes(presetAgency)) agencySel.value = presetAgency;
  }
  if (scopeSel) scopeSel.value = presetScope || 'interagency';
  updateRequestScopeFields();
  if (presetType) {
    const typeSel = document.getElementById('req-type');
    if (typeSel && [...typeSel.options].some(o => o.value === presetType)) typeSel.value = presetType;
    updateRequestLawRef();
  }
  modal.classList.remove('hidden');
}

function closeRequestModal() {
  document.getElementById('request-modal').classList.add('hidden');
}

function updateRequestScopeFields() {
  const scope = document.getElementById('req-scope')?.value || 'interagency';
  const p = getActivePersona();
  const agencyKey = getPersonaAgencyKey(p);
  const scopeMeta = REQUEST_SCOPES[scope];

  document.querySelectorAll('.req-scope-field').forEach(el => {
    const scopes = (el.dataset.scope || '').split(/\s+/);
    el.classList.toggle('hidden', !scopes.includes(scope));
  });

  const targetLabel = document.getElementById('req-target-label');
  if (targetLabel) {
    targetLabel.textContent = scope === 'intra_department' ? 'Кому в отделе' : 'Подразделение-исполнитель';
  }

  const channelEl = document.getElementById('req-channel-hint');
  if (channelEl) channelEl.textContent = `Канал: ${scopeMeta.channel}`;

  const submitBtn = document.getElementById('req-submit-btn');
  if (submitBtn) {
    submitBtn.textContent = scope === 'interagency'
      ? 'Отправить в СМЭВ'
      : scope === 'intra_agency'
        ? 'Отправить во внутренний контур'
        : 'Направить в отдел';
  }

  const titleEl = document.getElementById('request-modal-title');
  if (titleEl) titleEl.textContent = `Новый запрос · ${scopeMeta.label.toLowerCase()}`;

  const deptFrom = document.getElementById('req-dept-from');
  if (deptFrom) deptFrom.value = p.department || p.group;

  const agencyFrom = document.getElementById('req-agency-from');
  if (agencyFrom) {
    const a = agencyRegistry.find(x => x.id === agencyKey);
    agencyFrom.value = a ? a.name : (p.group || p.agency);
  }

  const typeSel = document.getElementById('req-type');
  if (!typeSel) return;

  if (scope === 'interagency') {
    updateRequestTypes();
    return;
  }

  const types = scope === 'intra_agency'
    ? (intraAgencyRequestTypes[agencyKey] || [])
    : (intraDepartmentRequestTypes[agencyKey] || []);

  typeSel.innerHTML = types.length
    ? types.map(t => `<option value="${t.type}">${t.label}</option>`).join('')
    : '<option value="">— нет типов для роли —</option>';

  const targetSel = document.getElementById('req-target');
  if (targetSel && types.length) {
    const first = types.find(t => t.type === typeSel.value) || types[0];
    const targets = first.units || first.targets || [];
    targetSel.innerHTML = targets.map(u => `<option value="${u}">${u}</option>`).join('');
  }

  updateRequestLawRef();
}

function updateRequestTypes() {
  const agency = document.getElementById('req-agency')?.value;
  const typeSel = document.getElementById('req-type');
  if (!typeSel) return;
  const types = requestTypesByAgency[agency] || [];
  typeSel.innerHTML = types.map(t => `<option value="${t.type}">${t.label}</option>`).join('');
  updateRequestLawRef();
}

function updateRequestLawRef() {
  const scope = document.getElementById('req-scope')?.value || 'interagency';
  const type = document.getElementById('req-type')?.value;
  const ref = document.getElementById('req-law-ref');
  let found = null;

  if (scope === 'interagency') {
    const agency = document.getElementById('req-agency')?.value;
    found = (requestTypesByAgency[agency] || []).find(t => t.type === type);
  } else {
    const agencyKey = getPersonaAgencyKey(getActivePersona());
    const pool = scope === 'intra_agency'
      ? intraAgencyRequestTypes[agencyKey]
      : intraDepartmentRequestTypes[agencyKey];
    found = (pool || []).find(t => t.type === type);
    if (found) {
      const targetSel = document.getElementById('req-target');
      if (targetSel) {
        const targets = found.units || found.targets || [];
        const prev = targetSel.value;
        targetSel.innerHTML = targets.map(u => `<option value="${u}">${u}</option>`).join('');
        if (targets.includes(prev)) targetSel.value = prev;
      }
    }
  }

  if (ref) ref.textContent = found ? `Правовая ссылка: ${found.law}` : '';
}

function submitNewRequest() {
  if (!canCreateRequest()) {
    showToast('Создание запросов недоступно для вашей роли (ПОЛ-003).');
    return;
  }
  const scope = document.getElementById('req-scope')?.value || 'interagency';
  const typeSel = document.getElementById('req-type');
  const typeLabel = typeSel?.selectedOptions[0]?.text || typeSel?.value;
  const legal = document.getElementById('req-legal')?.value.trim();
  if (!legal) { showToast('Укажите правовое основание (постановление).'); return; }
  if (!typeSel?.value) { showToast('Выберите тип запроса.'); return; }

  const p = getActivePersona();
  requestSeq += 1;
  const id = `Запрос-${requestSeq}`;
  const scopeMeta = REQUEST_SCOPES[scope];
  let target = '';
  let agency = p.agency;

  if (scope === 'interagency') {
    const agencyId = document.getElementById('req-agency').value;
    const a = agencyRegistry.find(x => x.id === agencyId);
    target = a ? a.name : agencyId;
    agency = target;
  } else if (scope === 'intra_agency') {
    target = document.getElementById('req-target')?.value || 'Подразделение';
  } else {
    target = document.getElementById('req-target')?.value || 'Отдел';
  }

  platformRequests.unshift({
    id,
    scope,
    type: typeLabel,
    target,
    from: p.department ? `${p.department} · ${p.name.split(' ')[0]}` : `${p.group} · ${p.role}`,
    agency: scope === 'interagency' ? target : (p.agency || getPersonaAgencyKey(p)),
    department: scope === 'intra_department' ? p.department : undefined,
    status: scope === 'interagency' ? 'submitted' : 'progress',
    sent: 'сегодня',
    sla: scope === 'interagency' ? 'по SLA' : scope === 'intra_agency' ? 'до 1 дня' : 'до 4 ч'
  });

  closeRequestModal();
  requestFilterScope = scope;
  renderRequests();
  showToast(`${id}: ${typeLabel} → ${target} (${scopeMeta.channel}). Основание: ${legal}`);
}

let activeGraphCaseId = null;

const graphNodes = [
  { id: 'p1', type: 'person', label: 'Подозреваемый А.', detail: 'Фигурант по делу ЕПСОК-2028-004521. Связь с московским делом установлена 05.02.2028.', caseId: 'ЕПСОК-2028-004521' },
  { id: 'ph1', type: 'phone', label: '+7 (900) 123-45-67', detail: 'SIM зарегистрирована на номинальное лицо. 847 исходящих за 30 дней.', caseId: 'ЕПСОК-2028-004521', sourceKey: 'phone:4567', sourceValue: '+79001234567' },
  { id: 'ph2', type: 'phone', label: '+7 (900) 987-89-01', detail: 'Общая SIM с делом в Казани (ЕПСОК-2028-002891).', caseId: 'ЕПСОК-2028-002891', sourceKey: 'phone:8901', sourceValue: '+79009878901' },
  { id: 'acc1', type: 'account', label: 'Счёт ***4521', detail: 'Получатель переводов от 23 потерпевших. Запрос РФМ исполнен 02.02.2028.', caseId: 'ЕПСОК-2028-001234', sourceKey: 'account:4521' },
  { id: 'c1', type: 'case', label: 'Дело Краснодар', detail: 'ЕПСОК-2028-004521 · 159.3 УК РФ · в работе.', caseId: 'ЕПСОК-2028-004521' },
  { id: 'c2', type: 'case', label: 'Дело Москва', detail: 'ЕПСОК-2028-001234 · 159.3 УК РФ · связь по счёту.', caseId: 'ЕПСОК-2028-001234' },
  { id: 'c3', type: 'case', label: 'Дело Казань', detail: 'ЕПСОК-2028-002891 · 159.3 УК РФ · связь по SIM.', caseId: 'ЕПСОК-2028-002891' },
  { id: 'org1', type: 'org', label: 'ООО «***»', detail: 'ИНН *** · номинальный директор. Запрос ФНС исполнен.', caseId: 'ЕПСОК-2028-001234' }
];

const graphEdges = [
  ['p1', 'ph1'], ['p1', 'ph2'], ['p1', 'acc1'], ['acc1', 'org1'],
  ['p1', 'c1'], ['acc1', 'c2'], ['ph2', 'c3'], ['c1', 'c2'], ['c2', 'c3']
];

const nodeColors = {
  person: '#61afef',
  phone: '#98c379',
  account: '#e5c07b',
  case: '#e06c75',
  org: '#c678dd',
  social: '#f78c6c',
  username: '#56b6c2'
};

const nodeTypeLabels = {
  person: 'Лицо',
  phone: 'Телефон',
  account: 'Счёт',
  case: 'Дело',
  org: 'Организация',
  social: 'Открытые источники',
  username: 'Никнейм'
};

const graphNodeCommunications = {
  ph1: {
    calls: [
      { time: '14.06.28 09:14', dir: 'out', peer: '+7 (918) 521-21-88', duration: '2:34', note: 'Повторный контакт' },
      { time: '13.06.28 22:08', dir: 'in', peer: '+7 (918) 234-55-12', duration: '0:47', note: 'Короткий входящий' },
      { time: '12.06.28 18:41', dir: 'out', peer: '+7 (918) 456-90-33', duration: '5:12', note: 'Уточнение реквизитов' },
      { time: '11.06.28 11:03', dir: 'out', peer: '+7 (918) 521-21-88', duration: '1:08', note: 'Первичный звонок' },
      { time: '10.06.28 07:55', dir: 'in', peer: 'Служба 900', duration: '0:22', note: 'Автоинформатор' }
    ],
    sms: [
      { time: '13.06.28 22:41', dir: 'in', peer: '+7 (918) 521-21-88', text: 'Переведите на карту до 23:00, иначе отмена сделки' },
      { time: '13.06.28 19:15', dir: 'out', peer: '+7 (918) 521-21-88', text: 'Реквизиты отправил в мессенджере, жду подтверждение' },
      { time: '12.06.28 14:02', dir: 'in', peer: '900', text: 'Списание 15 000 ₽. Карта *4521. Если не вы — 900' },
      { time: '11.06.28 10:44', dir: 'in', peer: '+7 (918) 521-21-88', text: 'Добрый день, по объявлению на Авито. Актуально?' }
    ]
  },
  ph2: {
    calls: [
      { time: '08.06.28 16:22', dir: 'out', peer: '+7 (843) 267-67-44', duration: '3:51', note: 'Связь с Казанью' },
      { time: '07.06.28 09:10', dir: 'in', peer: '+7 (900) 987-89-01', duration: '0:15', note: 'Пропущенный' },
      { time: '05.06.28 21:33', dir: 'out', peer: '+7 (843) 512-12-09', duration: '7:04', note: 'Ночной исходящий' }
    ],
    sms: [
      { time: '08.06.28 16:25', dir: 'out', peer: '+7 (843) 267-67-44', text: 'SIM активна, код получил. Передаю курьеру' },
      { time: '07.06.28 09:12', dir: 'in', peer: '+7 (843) 267-67-44', text: 'Напиши когда будешь на связи' },
      { time: '05.06.28 21:36', dir: 'out', peer: '+7 (843) 512-12-09', text: 'Новая SIM в обороте, старую выбросил' }
    ]
  },
  p1: {
    calls: [
      { time: '14.06.28 09:14', dir: 'out', peer: '+7 (900) 123-45-67 → (918) 521-21-88', duration: '2:34', note: 'Через основную SIM' },
      { time: '08.06.28 16:22', dir: 'out', peer: '+7 (900) 987-89-01 → (843) 267-67-44', duration: '3:51', note: 'Через резервную SIM' },
      { time: '05.06.28 21:33', dir: 'out', peer: '+7 (900) 987-89-01', duration: '7:04', note: 'Ночной контакт' }
    ],
    sms: [
      { time: '13.06.28 22:41', dir: 'in', peer: '+7 (900) 123-45-67', text: 'Входящее на основную SIM: требование перевода' },
      { time: '08.06.28 16:25', dir: 'out', peer: '+7 (900) 987-89-01', text: 'Исходящее с резервной SIM: передача кода' }
    ]
  }
};

let graphDetailTab = 'calls';
let graphDetailNodeId = null;
const GRAPH_COMM_DISPLAY_LIMIT = 5;

const graphPhoneOwnerLookup = {
  ph1: {
    status: 'nominal',
    statusLabel: 'Номинал',
    owner: 'Кузнецова Татьяна Викторовна',
    birthYear: 1968,
    regAddress: 'г. Краснодар, ул. Мира, 14',
    operator: 'МТС',
    registered: '12.03.2024',
    source: 'ГИАЦ · запрос оператору',
    note: 'Держатель SIM не совпадает с фигурантом · типичная схема номинальной регистрации'
  },
  ph2: {
    status: 'linked',
    statusLabel: 'Связь установлена',
    owner: 'Петров Сергей Александрович',
    birthYear: 1985,
    regAddress: 'г. Казань, ул. Баумана, 8',
    operator: 'Билайн',
    registered: '03.11.2023',
    source: 'ГИАЦ · ЕПСОК-2028-002891',
    note: 'SIM пересекается с делом в Казани · общий номер в цепочке переводов'
  }
};

const graphOwnerCheckState = {};
const graphPeerCheckState = {};

const graphPeerQuickLookup = {
  '9185212188': {
    status: 'suspect',
    statusLabel: 'В деле',
    owner: 'Андреев Сергей Викторович',
    birthYear: 1987,
    operator: 'МТС',
    region: 'Краснодарский край',
    source: 'ГИАЦ · быстрый запрос',
    note: 'Фигурант ЕПСОК-2028-004521 · повторяющиеся контакты'
  },
  '9182345512': {
    status: 'unknown',
    statusLabel: 'Не установлен',
    owner: '—',
    operator: 'МегаФон',
    region: 'Краснодарский край',
    source: 'ГИАЦ · оператор',
    note: 'Абонент не идентифицирован в ИБД · однократный входящий'
  },
  '9184569033': {
    status: 'nominal',
    statusLabel: 'Номинал',
    owner: 'Сидорова Мария Ивановна',
    birthYear: 1972,
    operator: 'Tele2',
    region: 'Краснодарский край',
    source: 'ГИАЦ · запрос оператору',
    note: 'Держатель SIM не совпадает с контрагентом по сделке'
  },
  '8432676744': {
    status: 'linked',
    statusLabel: 'Связь установлена',
    owner: 'Ибрагимов Р.К.',
    birthYear: 1991,
    operator: 'Билайн',
    region: 'Респ. Татарстан',
    source: 'ГИАЦ · ЕПСОК-2028-002891',
    note: 'Пересечение с делом в Казани · посредник по SIM'
  },
  '8435121209': {
    status: 'unknown',
    statusLabel: 'Не установлен',
    owner: '—',
    operator: 'МТС',
    region: 'Респ. Татарстан',
    source: 'ГИАЦ · оператор',
    note: 'Ночной исходящий · идентификация не завершена'
  },
  '9009878901': {
    status: 'linked',
    statusLabel: 'Связь установлена',
    owner: 'Петров Сергей Александрович',
    birthYear: 1985,
    operator: 'Билайн',
    region: 'Респ. Татарстан',
    source: 'ГИАЦ · ЕПСОК-2028-002891',
    note: 'Резервная SIM фигуранта · общий номер в цепочке'
  }
};

function commQuickCheckKey(nodeId, kind, index) {
  return `${nodeId}:${kind}:${index}`;
}

function extractPeerPhone(peer) {
  const s = String(peer || '');
  const target = s.includes('→') ? s.split('→').pop() : s;
  let digits = target.replace(/\D/g, '');
  if (digits.length === 11 && (digits.startsWith('7') || digits.startsWith('8'))) digits = digits.slice(1);
  return digits.length === 10 ? digits : '';
}

function isPeerCheckable(peer) {
  return extractPeerPhone(peer).length === 10;
}

function formatPhoneRu(value) {
  const digits = String(value || '').replace(/\D/g, '');
  let d = digits;
  if (d.length === 11 && d.startsWith('7')) d = d.slice(1);
  if (d.length === 10) {
    return `+7 (${d.slice(0, 3)}) ${d.slice(3, 6)}-${d.slice(6, 8)}-${d.slice(8, 10)}`;
  }
  return value || '—';
}

function formatPhoneCompact(value) {
  const formatted = formatPhoneRu(value);
  if (formatted.startsWith('+7 (')) {
    return formatted.replace('+7 (', '+7 ').replace(') ', ' ');
  }
  return formatted;
}

function getGraphNodeDisplayLabel(node) {
  if (!node) return '—';
  if (node.type === 'phone' && node.sourceValue) return formatPhoneRu(node.sourceValue);
  if (node.type === 'phone') return formatPhoneRu(node.label) !== '—' ? formatPhoneRu(node.label) : node.label;
  return node.label;
}

function getGraphCanvasLabel(node) {
  if (node.type === 'phone') {
    const raw = node.sourceValue || node.label;
    const compact = formatPhoneCompact(raw);
    return compact.length > 18 ? compact.slice(0, 17) + '…' : compact;
  }
  const text = node.label || '';
  return text.length > 22 ? text.slice(0, 20) + '…' : text;
}

function nodeHasCommunications(node) {
  return node && (node.type === 'phone' || node.type === 'person');
}

function nodeShowsCommsPanel(node) {
  return !!(node?.type === 'phone' && graphNodeCommunications[node.id]);
}

function getCommunicationsForNode(node) {
  if (!node) return { calls: [], sms: [] };
  if (graphNodeCommunications[node.id]) {
    const comm = graphNodeCommunications[node.id];
    return {
      calls: comm.calls.slice(0, GRAPH_COMM_DISPLAY_LIMIT),
      sms: comm.sms.slice(0, GRAPH_COMM_DISPLAY_LIMIT)
    };
  }
  if (node.type === 'person') {
    const linkedPhones = new Set();
    for (const [a, b] of graphEdges) {
      if (a !== node.id && b !== node.id) continue;
      const otherId = a === node.id ? b : a;
      const other = graphNodes.find(n => n.id === otherId);
      if (other?.type === 'phone') linkedPhones.add(other.id);
    }
    const calls = [];
    const sms = [];
    for (const pid of linkedPhones) {
      const comm = graphNodeCommunications[pid];
      if (!comm) continue;
      calls.push(...comm.calls);
      sms.push(...comm.sms);
    }
    calls.sort((x, y) => y.time.localeCompare(x.time));
    sms.sort((x, y) => y.time.localeCompare(x.time));
    return { calls: calls.slice(0, GRAPH_COMM_DISPLAY_LIMIT), sms: sms.slice(0, GRAPH_COMM_DISPLAY_LIMIT) };
  }
  return { calls: [], sms: [] };
}

function graphDetailFact(label, value) {
  if (!value) return '';
  return `<div><dt>${escapeHtml(label)}</dt><dd>${escapeHtml(value)}</dd></div>`;
}

function graphCommDirLabel(dir) {
  return dir === 'in' ? 'Вх' : 'Исх';
}

function graphNodeTypeAccent(type) {
  return nodeColors[type] || '#888';
}

function renderGraphCallsList(calls, nodeId) {
  const items = calls.slice(0, GRAPH_COMM_DISPLAY_LIMIT);
  if (!items.length) {
    return '<p class="graph-detail-empty">Нет зафиксированных вызовов за период наблюдения</p>';
  }
  return `<ul class="graph-comm-list">${items.map((c, i) => `
    <li class="graph-comm-card ${c.dir === 'in' ? 'is-in' : 'is-out'}">
      <div class="graph-comm-card-head">
        <span class="graph-comm-time">${escapeHtml(c.time)}</span>
        <span class="graph-comm-dir">${graphCommDirLabel(c.dir)}</span>
      </div>
      <div class="graph-comm-card-main">
        <span class="graph-comm-peer">${escapeHtml(c.peer)}</span>
        ${renderGraphCommQuickCheckAction(nodeId, 'calls', i, c.peer)}
      </div>
      <span class="graph-comm-meta">${escapeHtml(c.duration)}${c.note ? `<em>${escapeHtml(c.note)}</em>` : ''}</span>
      ${renderGraphCommQuickCheckResult(nodeId, 'calls', i, c.peer)}
    </li>`).join('')}</ul>`;
}

function renderGraphSmsList(messages, nodeId) {
  const items = messages.slice(0, GRAPH_COMM_DISPLAY_LIMIT);
  if (!items.length) {
    return '<p class="graph-detail-empty">Нет SMS за период наблюдения</p>';
  }
  return `<ul class="graph-comm-list">${items.map((m, i) => `
    <li class="graph-comm-card graph-comm-card-sms ${m.dir === 'in' ? 'is-in' : 'is-out'}">
      <div class="graph-comm-card-head">
        <span class="graph-comm-time">${escapeHtml(m.time)}</span>
        <span class="graph-comm-dir">${graphCommDirLabel(m.dir)}</span>
      </div>
      <div class="graph-comm-card-main">
        <span class="graph-comm-peer">${escapeHtml(m.peer)}</span>
        ${renderGraphCommQuickCheckAction(nodeId, 'sms', i, m.peer)}
      </div>
      <p class="graph-comm-sms">${escapeHtml(m.text)}</p>
      ${renderGraphCommQuickCheckResult(nodeId, 'sms', i, m.peer)}
    </li>`).join('')}</ul>`;
}

function renderGraphCommQuickCheckAction(nodeId, kind, index, peer) {
  if (!isPeerCheckable(peer)) return '';
  const stateKey = commQuickCheckKey(nodeId, kind, index);
  const state = graphPeerCheckState[stateKey];
  if (state === 'loading') {
    return `<span class="graph-comm-check-loading">ГИАЦ…</span>`;
  }
  if (state === 'done') {
    return `<button type="button" class="graph-comm-check-btn is-done" data-peer-check data-node-id="${nodeId}" data-kind="${kind}" data-index="${index}" title="Обновить проверку">↻</button>`;
  }
  return `<button type="button" class="graph-comm-check-btn" data-peer-check data-node-id="${nodeId}" data-kind="${kind}" data-index="${index}" title="Быстрая проверка по ГИАЦ (ПОЛ-007)"><span class="graph-comm-check-icon" aria-hidden="true">⌕</span> Проверить</button>`;
}

function renderGraphCommQuickCheckResult(nodeId, kind, index, peer) {
  if (!isPeerCheckable(peer)) {
    return `<p class="graph-comm-quick-skip muted">Служебный номер · проверка недоступна</p>`;
  }
  const stateKey = commQuickCheckKey(nodeId, kind, index);
  const state = graphPeerCheckState[stateKey];
  if (state !== 'done') return '';
  const phoneKey = extractPeerPhone(peer);
  const lookup = graphPeerQuickLookup[phoneKey];
  if (!lookup) {
    return `<p class="graph-comm-quick-empty muted">Абонент не найден в ГИАЦ</p>`;
  }
  const badgeClass = lookup.status === 'suspect' ? 'is-match' : lookup.status === 'nominal' ? 'is-nominal' : lookup.status === 'linked' ? 'is-match' : 'is-pending';
  return `<div class="graph-comm-quick-result-block">
    <span class="graph-comm-quick-badge ${badgeClass}">${escapeHtml(lookup.statusLabel)}</span>
    <span class="graph-comm-quick-owner">${escapeHtml(lookup.owner)}</span>
    <span class="graph-comm-quick-meta muted">${escapeHtml(lookup.operator)} · ${escapeHtml(lookup.region || '—')}</span>
    <p class="graph-comm-quick-note">${escapeHtml(lookup.note)}</p>
  </div>`;
}

function refreshGraphCommsPanelOnly() {
  const node = graphNodes.find(n => n.id === graphDetailNodeId);
  const commsPanel = document.getElementById('graph-comms-panel');
  if (node && nodeShowsCommsPanel(node) && commsPanel) {
    commsPanel.innerHTML = renderGraphCommsPanel(node);
  }
}

function runGraphPeerQuickCheck(nodeId, kind, index) {
  const node = graphNodes.find(n => n.id === nodeId);
  if (!node) return;
  const comm = getCommunicationsForNode(node);
  const list = kind === 'sms' ? comm.sms : comm.calls;
  const item = list[index];
  if (!item || !isPeerCheckable(item.peer)) return;
  const stateKey = commQuickCheckKey(nodeId, kind, index);
  graphPeerCheckState[stateKey] = 'loading';
  refreshGraphCommsPanelOnly();
  setTimeout(() => {
    const phoneKey = extractPeerPhone(item.peer);
    graphPeerCheckState[stateKey] = 'done';
    refreshGraphCommsPanelOnly();
    const lookup = graphPeerQuickLookup[phoneKey];
    if (lookup) {
      showToast(`ГИАЦ: ${lookup.owner} · ${lookup.statusLabel}`);
    } else {
      showToast('Абонент не найден в ГИАЦ (демо-контур)');
    }
  }, 550);
}

window.runGraphPeerQuickCheck = runGraphPeerQuickCheck;

function graphDetailSimInfo(node) {
  if (node.type !== 'phone') return '';
  if (node.id === 'ph1') return 'МТС · номинал · 847 исх. / 30 дн.';
  if (node.id === 'ph2') return 'Билайн · общая SIM · Казань';
  return 'оператор уточняется';
}

function renderGraphOwnerCheck(node) {
  if (node.type !== 'phone') return '';
  const lookup = graphPhoneOwnerLookup[node.id];
  const state = graphOwnerCheckState[node.id] || (lookup ? 'done' : 'idle');
  if (state === 'loading') {
    return `<div class="graph-detail-owner">
      <div class="graph-detail-owner-head">
        <span class="graph-detail-owner-title">Принадлежность номера</span>
      </div>
      <p class="graph-detail-owner-loading">Запрос в ГИАЦ…</p>
    </div>`;
  }
  if (state !== 'done' || !lookup) {
    return `<div class="graph-detail-owner">
      <div class="graph-detail-owner-head">
        <span class="graph-detail-owner-title">Принадлежность номера</span>
      </div>
      <p class="muted" style="font-size:0.72rem;margin:0">Быстрая проверка по ГИАЦ и данным оператора (ПОЛ-007)</p>
      <div class="graph-detail-owner-actions">
        <button type="button" class="btn-sm" onclick="runGraphOwnerCheck('${node.id}')">Проверить владельца</button>
      </div>
    </div>`;
  }
  const badgeClass = lookup.status === 'nominal' ? 'is-nominal' : lookup.status === 'linked' ? 'is-match' : 'is-pending';
  return `<div class="graph-detail-owner">
    <div class="graph-detail-owner-head">
      <span class="graph-detail-owner-title">Принадлежность номера</span>
      <span class="graph-detail-owner-badge ${badgeClass}">${escapeHtml(lookup.statusLabel)}</span>
    </div>
    <dl class="graph-detail-owner-grid">
      <div class="graph-detail-owner-field graph-detail-owner-field-wide"><dt>Владелец</dt><dd>${escapeHtml(lookup.owner)}</dd></div>
      <div class="graph-detail-owner-field"><dt>Год рожд.</dt><dd>${lookup.birthYear || '—'}</dd></div>
      <div class="graph-detail-owner-field"><dt>Оператор</dt><dd>${escapeHtml(lookup.operator)} · с ${escapeHtml(lookup.registered)}</dd></div>
      <div class="graph-detail-owner-field graph-detail-owner-field-wide"><dt>Адрес рег.</dt><dd>${escapeHtml(lookup.regAddress)}</dd></div>
      <div class="graph-detail-owner-field graph-detail-owner-field-wide"><dt>Источник</dt><dd>${escapeHtml(lookup.source)}</dd></div>
    </dl>
    <p class="graph-detail-owner-note">${escapeHtml(lookup.note)}</p>
    <div class="graph-detail-owner-actions">
      <button type="button" class="btn-sm graph-detail-owner-btn" onclick="runGraphOwnerCheck('${node.id}')">Обновить проверку</button>
    </div>
  </div>`;
}

function runGraphOwnerCheck(nodeId) {
  const node = graphNodes.find(n => n.id === nodeId);
  if (!node || node.type !== 'phone') return;
  graphOwnerCheckState[nodeId] = 'loading';
  refreshGraphDetailPanel();
  setTimeout(() => {
    graphOwnerCheckState[nodeId] = graphPhoneOwnerLookup[nodeId] ? 'done' : 'idle';
    refreshGraphDetailPanel();
    if (graphPhoneOwnerLookup[nodeId]) {
      showToast(`ГИАЦ: ${graphPhoneOwnerLookup[nodeId].owner}`);
    } else {
      showToast('Данные оператора не найдены в демо-контуре');
    }
  }, 650);
}

function resetGraphSidePanels() {
  const commsPanel = document.getElementById('graph-comms-panel');
  const sideStack = document.querySelector('.graph-side-stack');
  if (commsPanel) {
    commsPanel.hidden = true;
    commsPanel.innerHTML = '';
  }
  sideStack?.classList.remove('has-comms');
  document.querySelector('.graph-workspace')?.classList.remove('has-comms-panel');
}

function refreshGraphDetailPanel() {
  const node = graphNodes.find(n => n.id === graphDetailNodeId);
  const panel = document.getElementById('node-detail');
  const commsPanel = document.getElementById('graph-comms-panel');
  const sideStack = document.querySelector('.graph-side-stack');
  const showComms = nodeShowsCommsPanel(node);
  sideStack?.classList.toggle('has-comms', showComms);
  if (commsPanel) {
    commsPanel.hidden = !showComms;
    if (showComms) commsPanel.innerHTML = renderGraphCommsPanel(node);
    else commsPanel.innerHTML = '';
  }
  if (!panel) return;
  if (!node) {
    panel.classList.remove('is-active');
    panel.innerHTML = `<div class="graph-detail-placeholder">
      <span class="graph-detail-placeholder-icon" aria-hidden="true">◎</span>
      <h2>Узел не выбран</h2>
      <p class="muted">Кликните узел на графе — карточка откроется здесь</p>
    </div>`;
    return;
  }
  panel.classList.add('is-active');
  panel.innerHTML = renderGraphDetailPanel(node);
}

function renderGraphCommsPanel(node) {
  if (!nodeShowsCommsPanel(node)) return '';
  const comm = getCommunicationsForNode(node);
  const tab = ['calls', 'sms'].includes(graphDetailTab) ? graphDetailTab : 'calls';
  const callsPanel = tab === 'calls' ? '' : ' hidden';
  const smsPanel = tab === 'sms' ? '' : ' hidden';
  const label = getGraphNodeDisplayLabel(node);
  return `
    <div class="graph-comms-shell">
      <div class="graph-comms-head">
        <h3 class="graph-comms-title">Коммуникации</h3>
        <span class="graph-comms-sub mono">${escapeHtml(label)}</span>
        <p class="graph-comms-hint muted">Быстрая проверка абонента по каждому контакту · ГИАЦ (ПОЛ-007)</p>
      </div>
      <div class="graph-detail-tabs" role="tablist">
        <button type="button" role="tab" class="graph-detail-tab${tab === 'calls' ? ' active' : ''}" onclick="switchGraphDetailTab('calls')">Вызовы<span class="graph-detail-tab-count">${comm.calls.length}</span></button>
        <button type="button" role="tab" class="graph-detail-tab${tab === 'sms' ? ' active' : ''}" onclick="switchGraphDetailTab('sms')">SMS<span class="graph-detail-tab-count">${comm.sms.length}</span></button>
      </div>
      <div class="graph-comms-body">
        <div class="graph-detail-tab-panel${callsPanel}" data-tab-panel="calls">${renderGraphCallsList(comm.calls, node.id)}</div>
        <div class="graph-detail-tab-panel${smsPanel}" data-tab-panel="sms">${renderGraphSmsList(comm.sms, node.id)}</div>
      </div>
    </div>`;
}

function renderGraphDetailPanel(node) {
  if (!node) {
    return `<div class="graph-detail-placeholder">
      <span class="graph-detail-placeholder-icon" aria-hidden="true">◎</span>
      <h2>Узел не выбран</h2>
      <p class="muted">Кликните узел на графе — карточка откроется здесь</p>
    </div>`;
  }
  const displayLabel = getGraphNodeDisplayLabel(node);
  const titleClass = node.type === 'phone' ? 'graph-detail-phone' : '';
  const accent = graphNodeTypeAccent(node.type);
  return `
    <div class="graph-detail-shell">
      <div class="graph-detail-head" style="--node-accent:${accent}">
        <div class="graph-detail-head-main">
          <span class="graph-detail-type-dot" aria-hidden="true"></span>
          <div class="graph-detail-identity">
            <h2 class="${titleClass}">${escapeHtml(displayLabel)}</h2>
            <span class="graph-detail-type">${escapeHtml(nodeTypeLabels[node.type] || node.type)}</span>
          </div>
        </div>
        <button type="button" class="graph-detail-close" onclick="clearGraphNodeSelection()" title="Закрыть">×</button>
      </div>
      <div class="graph-detail-body">
        <dl class="graph-detail-facts">
          ${graphDetailFact('Дело', node.caseId)}
          ${node.type === 'phone' ? graphDetailFact('Номер', displayLabel) : ''}
          ${node.type === 'phone' ? graphDetailFact('SIM', graphDetailSimInfo(node)) : ''}
          ${graphDetailFact('Кластер', node.caseId === 'ЕПСОК-2028-004521' || node.caseId === 'ЕПСОК-2028-010112' ? 'МВ-2847' : '—')}
        </dl>
        ${node.detail ? `<p class="graph-detail-summary">${escapeHtml(node.detail)}</p>` : ''}
        ${node.type === 'phone' ? renderGraphOwnerCheck(node) : ''}
      </div>
    </div>`;
}

function clearGraphNodeSelection() {
  graphView.selectNode(null);
}

function switchGraphDetailTab(tab) {
  if (!['calls', 'sms'].includes(tab)) return;
  graphDetailTab = tab;
  refreshGraphCommsPanelOnly();
}

const graphView = (() => {
  let simNodes = [];
  let currentEdges = [];
  let selectedId = null;
  let hoveredId = null;
  let canvas;
  let ctx;
  let viewport;
  let width = 800;
  let height = 480;
  let dpr = 1;
  let animId = null;
  let alpha = 0;
  let active = false;
  let pendingLayoutSnapshot = false;
  const layoutSnapshotByCase = {};

  const transform = { x: 0, y: 0, k: 1 };
  let panning = false;
  let draggingId = null;
  let dragMoved = false;
  let dragStart = { x: 0, y: 0 };
  let cameraFollowId = null;
  let pointer = { x: 0, y: 0 };

  function isAnchorNode(nodeId) {
    return !!nodeId && nodeId === getFocusNodeId();
  }

  function getAnchorSim() {
    const id = getFocusNodeId();
    return id ? getSim(id) : null;
  }

  function translateCluster(dx, dy, exceptId) {
    if (!dx && !dy) return;
    for (const node of simNodes) {
      if (node.id === exceptId) continue;
      node.x += dx;
      node.y += dy;
      if (node.fx != null) {
        node.fx += dx;
        node.fy += dy;
      }
      node.vx = 0;
      node.vy = 0;
    }
  }

  function moveDraggedNode(node, worldX, worldY) {
    const prevX = node.fx ?? node.x;
    const prevY = node.fy ?? node.y;
    const dx = worldX - prevX;
    const dy = worldY - prevY;
    node.fx = worldX;
    node.fy = worldY;
    node.x = worldX;
    node.y = worldY;
    if (isAnchorNode(node.id)) translateCluster(dx, dy, node.id);
  }

  const cfg = {
    linkDistance: 105,
    linkStrength: 0.42,
    charge: -480,
    collisionPad: 36,
    centerStrength: 0.035,
    velocityDecay: 0.42,
    alphaMin: 0.002,
    alphaTarget: 0
  };

  function radius(type) {
    return type === 'case' ? 11 : 9;
  }

  function reloadEdges() {
    if (!activeGraphCaseId) {
      currentEdges = [];
      return;
    }
    const ids = new Set(graphNodes.filter(n => n.caseId === activeGraphCaseId).map(n => n.id));
    currentEdges = graphEdges.filter(([a, b]) => ids.has(a) && ids.has(b));
  }

  function syncNodes(keepPositions) {
    const prev = new Map(simNodes.map(n => [n.id, n]));
    const defs = activeGraphCaseId
      ? graphNodes.filter(n => n.caseId === activeGraphCaseId)
      : [];
    const focusId = keepPositions ? null : getFocusNodeId();
    reloadEdges();
    simNodes = defs.map((def) => {
      const old = prev.get(def.id);
      let x;
      let y;
      if (keepPositions && old) {
        x = old.x;
        y = old.y;
      } else if (def.id === focusId) {
        x = width / 2;
        y = height / 2;
      } else {
        const others = defs.filter(d => d.id !== focusId);
        const idx = Math.max(0, others.findIndex(d => d.id === def.id));
        const angle = (idx / Math.max(others.length, 1)) * Math.PI * 2 - Math.PI / 2;
        x = width / 2 + Math.cos(angle) * 130;
        y = height / 2 + Math.sin(angle) * 100;
      }
      return {
        ...def,
        r: radius(def.type),
        x,
        y,
        vx: keepPositions && old ? old.vx * 0.5 : 0,
        vy: keepPositions && old ? old.vy * 0.5 : 0,
        fx: null,
        fy: null
      };
    });
  }

  function getSim(id) {
    return simNodes.find(n => n.id === id);
  }

  function getFocusNodeId() {
    if (!activeGraphCaseId) {
      return simNodes.find(n => n.type === 'person')?.id ?? simNodes[0]?.id ?? null;
    }
    const anchor = typeof GRAPH_CASE_ANCHORS !== 'undefined' ? GRAPH_CASE_ANCHORS[activeGraphCaseId] : null;
    if (anchor?.anchorId && graphNodes.some(n => n.caseId === activeGraphCaseId && n.id === anchor.anchorId)) {
      return anchor.anchorId;
    }
    const person = graphNodes.find(n => n.caseId === activeGraphCaseId && n.type === 'person');
    return person?.id ?? simNodes.find(n => n.caseId === activeGraphCaseId)?.id ?? null;
  }

  function focusOnNode(nodeId, opts = {}) {
    const node = nodeId ? getSim(nodeId) : null;
    if (!node) return;
    const preserveZoom = opts.preserveZoom !== false;
    if (!preserveZoom) {
      let span = node.r + 90;
      for (const n of simNodes) {
        if (n.id === node.id) continue;
        span = Math.max(span, Math.hypot(n.x - node.x, n.y - node.y) + n.r + 52);
      }
      const k = Math.min((width - 96) / (span * 2), (height - 96) / (span * 2), 1.25);
      transform.k = Math.max(0.65, Math.min(k, 1.25));
    }
    transform.x = width / 2 - node.x * transform.k;
    transform.y = height / 2 - node.y * transform.k;
  }

  function focusOnCenter(nodeId) {
    const center = nodeId ? getSim(nodeId) : null;
    if (!center) {
      fitView();
      return;
    }
    focusOnNode(nodeId, { preserveZoom: false });
  }

  function screenToWorld(sx, sy) {
    return {
      x: (sx - transform.x) / transform.k,
      y: (sy - transform.y) / transform.k
    };
  }

  function pointerWorld() {
    return screenToWorld(pointer.x, pointer.y);
  }

  function tick() {
    const n = simNodes.length;
    if (n < 2) return;

    const anchor = getAnchorSim();

    if (!anchor) {
      let cx = 0;
      let cy = 0;
      for (const node of simNodes) {
        cx += node.x;
        cy += node.y;
      }
      cx = cx / n - width / 2;
      cy = cy / n - height / 2;
      for (const node of simNodes) {
        if (node.fx != null) continue;
        node.vx -= cx * cfg.centerStrength * alpha;
        node.vy -= cy * cfg.centerStrength * alpha;
      }
    }

    const anchorId = anchor?.id;
    const hubDrag = draggingId && anchorId && draggingId === anchorId;

    for (let i = 0; i < n; i++) {
      for (let j = i + 1; j < n; j++) {
        const a = simNodes[i];
        const b = simNodes[j];
        let dx = b.x - a.x;
        let dy = b.y - a.y;
        let dist2 = dx * dx + dy * dy;
        if (dist2 < 100) dist2 = 100;
        const f = (cfg.charge / dist2) * alpha;
        const dist = Math.sqrt(dist2);
        dx /= dist;
        dy /= dist;
        if (a.fx == null) { a.vx -= dx * f; a.vy -= dy * f; }
        if (b.fx == null) { b.vx += dx * f; b.vy += dy * f; }
      }
    }

    for (const [source, target] of currentEdges) {
      const a = getSim(source);
      const b = getSim(target);
      if (!a || !b) continue;
      let dx = b.x - a.x;
      let dy = b.y - a.y;
      const dist = Math.hypot(dx, dy) || 0.01;
      let strength = cfg.linkStrength;
      if (hubDrag && anchorId && (source === anchorId || target === anchorId)) {
        strength = Math.min(0.92, strength * 2.4);
      }
      const pull = ((dist - cfg.linkDistance) / dist) * strength * alpha;
      dx *= pull;
      dy *= pull;
      if (a.fx == null) { a.vx += dx; a.vy += dy; }
      if (b.fx == null) { b.vx -= dx; b.vy -= dy; }
    }

    for (let i = 0; i < n; i++) {
      for (let j = i + 1; j < n; j++) {
        const a = simNodes[i];
        const b = simNodes[j];
        let dx = b.x - a.x;
        let dy = b.y - a.y;
        const dist = Math.hypot(dx, dy) || 0.01;
        const minDist = a.r + b.r + cfg.collisionPad;
        if (dist < minDist) {
          const push = ((minDist - dist) / dist) * 0.55 * alpha;
          dx *= push;
          dy *= push;
          if (a.fx == null) { a.x -= dx; a.y -= dy; }
          if (b.fx == null) { b.x += dx; b.y += dy; }
        }
      }
    }

    for (const node of simNodes) {
      if (node.fx != null) {
        node.x = node.fx;
        node.y = node.fy;
        node.vx = 0;
        node.vy = 0;
        continue;
      }
      node.vx *= cfg.velocityDecay;
      node.vy *= cfg.velocityDecay;
      node.x += node.vx;
      node.y += node.vy;
    }
  }

  function drawDots() {
    const step = Math.max(18, 22 * transform.k);
    const offX = ((transform.x % step) + step) % step;
    const offY = ((transform.y % step) + step) % step;
    ctx.fillStyle = 'rgba(255, 255, 255, 0.045)';
    for (let x = offX; x < width; x += step) {
      for (let y = offY; y < height; y += step) {
        ctx.beginPath();
        ctx.arc(x, y, 1, 0, Math.PI * 2);
        ctx.fill();
      }
    }
  }

  function drawLabel(node, emphasized) {
    const fontSize = emphasized ? 11 : 10;
    ctx.font = `${emphasized ? 600 : 500} ${fontSize}px "Golos Text", sans-serif`;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';
    const y = node.y + node.r + 8;
    const text = getGraphCanvasLabel(node);
    const tw = Math.min(ctx.measureText(text).width + 12, 132);
    const h = fontSize + 8;
    const lx = node.x - tw / 2;
    ctx.fillStyle = emphasized ? 'rgba(8, 10, 22, 0.92)' : 'rgba(8, 10, 22, 0.78)';
    ctx.fillRect(lx, y - 3, tw, h);
    if (emphasized) {
      ctx.strokeStyle = 'rgba(97, 175, 239, 0.45)';
      ctx.lineWidth = 1 / Math.max(transform.k, 0.5);
      ctx.strokeRect(lx, y - 3, tw, h);
    }
    ctx.fillStyle = emphasized ? '#f0f0f8' : 'rgba(236, 236, 244, 0.82)';
    ctx.fillText(text, node.x, y, tw - 10);
  }

  function drawGraphBackground() {
    const g = ctx.createRadialGradient(width * 0.5, height * 0.45, 0, width * 0.5, height * 0.5, Math.max(width, height) * 0.75);
    g.addColorStop(0, '#1a1a28');
    g.addColorStop(0.55, '#12121c');
    g.addColorStop(1, '#0c0c14');
    ctx.fillStyle = g;
    ctx.fillRect(0, 0, width, height);
  }

  function render() {
    if (!ctx) return;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, width, height);
    drawGraphBackground();
    drawDots();

    ctx.save();
    ctx.translate(transform.x, transform.y);
    ctx.scale(transform.k, transform.k);

    for (const [source, target] of currentEdges) {
      const a = getSim(source);
      const b = getSim(target);
      if (!a || !b) continue;
      const lit = selectedId && (source === selectedId || target === selectedId);
      ctx.beginPath();
      ctx.moveTo(a.x, a.y);
      ctx.lineTo(b.x, b.y);
      if (lit) {
        ctx.strokeStyle = 'rgba(97, 175, 239, 0.75)';
        ctx.shadowColor = 'rgba(97, 175, 239, 0.35)';
        ctx.shadowBlur = 6 / transform.k;
      } else {
        ctx.strokeStyle = 'rgba(255, 255, 255, 0.12)';
        ctx.shadowBlur = 0;
      }
      ctx.lineWidth = (lit ? 2 : 1) / transform.k;
      ctx.stroke();
      ctx.shadowBlur = 0;
    }

    for (const node of simNodes) {
      const isSel = node.id === selectedId;
      const isHov = node.id === hoveredId;
      const color = nodeColors[node.type] || '#888';
      const showLabel = isSel || isHov || transform.k >= 0.55;

      if (isSel || isHov) {
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.r + 9, 0, Math.PI * 2);
        ctx.fillStyle = isSel ? color + '55' : color + '33';
        ctx.fill();
      }

      ctx.beginPath();
      ctx.arc(node.x, node.y, node.r, 0, Math.PI * 2);
      if (isSel) {
        ctx.fillStyle = '#f4f4fa';
        ctx.shadowColor = color;
        ctx.shadowBlur = 10 / transform.k;
      } else {
        ctx.fillStyle = color;
        ctx.shadowBlur = 0;
      }
      ctx.fill();
      ctx.shadowBlur = 0;

      if (isSel) {
        ctx.strokeStyle = color;
        ctx.lineWidth = 2.5 / transform.k;
        ctx.stroke();
      } else if (isHov) {
        ctx.strokeStyle = 'rgba(255,255,255,0.35)';
        ctx.lineWidth = 1.2 / transform.k;
        ctx.stroke();
      }

      if (showLabel) drawLabel(node, isSel || isHov);
    }

    ctx.restore();
    updateMeta();
  }

  function updateMeta() {
    const el = document.getElementById('graph-meta');
    if (el) {
      el.textContent = activeGraphCaseId
        ? `${simNodes.length} узлов · ${currentEdges.length} связей · ×${transform.k.toFixed(1)}`
        : '—';
    }
  }

  function loop() {
    if (!active) {
      animId = null;
      return;
    }
    if (alpha > cfg.alphaMin || draggingId) {
      tick();
      alpha += (cfg.alphaTarget - alpha) * 0.06;
      if (alpha < cfg.alphaMin) alpha = cfg.alphaMin;
      if (cameraFollowId && alpha > cfg.alphaMin + 0.02) {
        focusOnNode(cameraFollowId, { preserveZoom: true });
      }
    } else if (pendingLayoutSnapshot) {
      focusOnCenter(getFocusNodeId());
      snapshotLayout();
      cameraFollowId = null;
    } else if (cameraFollowId) {
      cameraFollowId = null;
    }
    render();
    animId = requestAnimationFrame(loop);
  }

  function relayout() {
    for (const node of simNodes) {
      node.fx = null;
      node.fy = null;
      node.vx = (Math.random() - 0.5) * 2;
      node.vy = (Math.random() - 0.5) * 2;
    }
    alpha = 1;
  }

  function fitView(pad = 56) {
    if (!simNodes.length) return;
    let minX = Infinity;
    let maxX = -Infinity;
    let minY = Infinity;
    let maxY = -Infinity;
    for (const node of simNodes) {
      minX = Math.min(minX, node.x - 50);
      maxX = Math.max(maxX, node.x + 50);
      minY = Math.min(minY, node.y - 50);
      maxY = Math.max(maxY, node.y + 56);
    }
    const gw = maxX - minX || 1;
    const gh = maxY - minY || 1;
    const k = Math.min((width - pad * 2) / gw, (height - pad * 2) / gh, 2.2);
    transform.k = Math.max(0.3, Math.min(k, 2.5));
    transform.x = width / 2 - (minX + gw / 2) * transform.k;
    transform.y = height / 2 - (minY + gh / 2) * transform.k;
  }

  function hitTest(wx, wy) {
    for (let i = simNodes.length - 1; i >= 0; i--) {
      const node = simNodes[i];
      const dx = wx - node.x;
      const dy = wy - node.y;
      if (dx * dx + dy * dy <= (node.r + 8) ** 2) return node;
    }
    return null;
  }

  function snapshotLayout() {
    if (!activeGraphCaseId) return;
    const nodes = {};
    for (const node of simNodes) {
      nodes[node.id] = { x: node.x, y: node.y, fx: node.fx, fy: node.fy };
    }
    layoutSnapshotByCase[activeGraphCaseId] = {
      nodes,
      camera: { x: transform.x, y: transform.y, k: transform.k }
    };
    pendingLayoutSnapshot = false;
  }

  function restoreCamera(camera) {
    if (camera && Number.isFinite(camera.x) && Number.isFinite(camera.y) && Number.isFinite(camera.k)) {
      transform.x = camera.x;
      transform.y = camera.y;
      transform.k = camera.k;
      return;
    }
    focusOnCenter(getFocusNodeId());
  }

  function resetPositions() {
    const snap = layoutSnapshotByCase[activeGraphCaseId];
    if (!snap) {
      showToast('Исходное расположение ещё не зафиксировано');
      return;
    }
    const nodes = snap.nodes || snap;
    for (const node of simNodes) {
      const pos = nodes[node.id];
      if (!pos) continue;
      node.x = pos.x;
      node.y = pos.y;
      node.fx = pos.fx;
      node.fy = pos.fy;
      node.vx = 0;
      node.vy = 0;
    }
    restoreCamera(snap.camera);
    alpha = Math.max(alpha, 0.35);
    render();
    showToast('Узлы и камера восстановлены');
  }

  function showDetail(node) {
    graphDetailNodeId = node?.id ?? null;
    if (node?.type === 'phone' && graphPhoneOwnerLookup[node.id] && graphOwnerCheckState[node.id] !== 'loading') {
      graphOwnerCheckState[node.id] = 'done';
    }
    if (node?.type === 'phone' && nodeHasCommunications(node) && !['calls', 'sms'].includes(graphDetailTab)) {
      graphDetailTab = 'calls';
    }
    refreshGraphDetailPanel();
  }

  function selectNode(node) {
    const prev = selectedId;
    selectedId = node?.id ?? null;
    if (node) {
      cameraFollowId = node.id;
      if (node.id !== prev) focusOnNode(node.id, { preserveZoom: true });
    } else {
      cameraFollowId = null;
    }
    showDetail(node);
    render();
  }

  function resize(recenter = false) {
    if (!viewport || !canvas) return;
    const rect = viewport.getBoundingClientRect();
    const newWidth = Math.max(320, Math.floor(rect.width));
    const newHeight = Math.max(280, Math.floor(rect.height));
    const prevW = width;
    const prevH = height;
    const worldCx = prevW > 0 ? (prevW / 2 - transform.x) / transform.k : 0;
    const worldCy = prevH > 0 ? (prevH / 2 - transform.y) / transform.k : 0;

    width = newWidth;
    height = newHeight;
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = width * dpr;
    canvas.height = height * dpr;
    canvas.style.width = `${width}px`;
    canvas.style.height = `${height}px`;

    if (recenter && simNodes.length) {
      if (selectedId) focusOnNode(selectedId, { preserveZoom: true });
      else if (activeGraphCaseId) focusOnCenter(getFocusNodeId());
      else fitView();
    } else if (prevW > 0 && prevH > 0) {
      transform.x = width / 2 - worldCx * transform.k;
      transform.y = height / 2 - worldCy * transform.k;
    }
    render();
  }

  function zoomAt(factor, sx, sy) {
    const before = screenToWorld(sx, sy);
    transform.k = Math.max(0.25, Math.min(3, transform.k * factor));
    const after = screenToWorld(sx, sy);
    transform.x += (after.x - before.x) * transform.k;
    transform.y += (after.y - before.y) * transform.k;
    render();
  }

  function onPointerDown(e) {
    if (!active) return;
    const rect = canvas.getBoundingClientRect();
    pointer.x = e.clientX - rect.left;
    pointer.y = e.clientY - rect.top;
    dragStart = { x: pointer.x, y: pointer.y };
    dragMoved = false;
    const world = pointerWorld();
    const hit = hitTest(world.x, world.y);
    if (hit) {
      draggingId = hit.id;
      viewport.classList.add('is-dragging-node');
    } else {
      cameraFollowId = null;
      panning = true;
      viewport.classList.add('is-panning');
    }
    canvas.setPointerCapture(e.pointerId);
  }

  function onPointerMove(e) {
    if (!active) return;
    const rect = canvas.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;

    if (draggingId) {
      const node = getSim(draggingId);
      if (node) {
        if (!dragMoved && Math.hypot(x - dragStart.x, y - dragStart.y) > 5) {
          dragMoved = true;
          const world = screenToWorld(x, y);
          moveDraggedNode(node, world.x, world.y);
          alpha = Math.max(alpha, isAnchorNode(draggingId) ? 0.45 : 0.3);
          if (isAnchorNode(draggingId)) render();
        } else if (dragMoved) {
          const world = screenToWorld(x, y);
          moveDraggedNode(node, world.x, world.y);
          alpha = Math.max(alpha, isAnchorNode(draggingId) ? 0.45 : 0.25);
          if (isAnchorNode(draggingId)) render();
        }
      }
      pointer.x = x;
      pointer.y = y;
      return;
    }

    if (panning) {
      transform.x += x - pointer.x;
      transform.y += y - pointer.y;
      pointer.x = x;
      pointer.y = y;
      render();
      return;
    }

    pointer.x = x;
    pointer.y = y;
    const hit = hitTest(pointerWorld().x, pointerWorld().y);
    const next = hit?.id ?? null;
    if (next !== hoveredId) {
      hoveredId = next;
      render();
    }
  }

  function onPointerUp(e) {
    if (draggingId) {
      const node = getSim(draggingId);
      if (node) {
        if (dragMoved) {
          if (!e.shiftKey) {
            node.fx = null;
            node.fy = null;
          }
          alpha = Math.max(alpha, 0.5);
          selectNode(node);
        } else {
          selectNode(node);
        }
      }
      draggingId = null;
      dragMoved = false;
      viewport.classList.remove('is-dragging-node');
    }
    if (panning) {
      panning = false;
      viewport.classList.remove('is-panning');
    }
    try { canvas.releasePointerCapture(e.pointerId); } catch (_) { /* noop */ }
  }

  function onWheel(e) {
    if (!active) return;
    e.preventDefault();
    const rect = canvas.getBoundingClientRect();
    const sx = e.clientX - rect.left;
    const sy = e.clientY - rect.top;
    zoomAt(e.deltaY < 0 ? 1.12 : 0.9, sx, sy);
  }

  function onDblClick(e) {
    if (!active) return;
    const rect = canvas.getBoundingClientRect();
    const world = screenToWorld(e.clientX - rect.left, e.clientY - rect.top);
    const hit = hitTest(world.x, world.y);
    if (hit) {
      hit.fx = null;
      hit.fy = null;
      alpha = Math.max(alpha, 0.6);
    } else {
      cameraFollowId = null;
      fitView();
    }
    render();
  }

  function init() {
    canvas = document.getElementById('graph-canvas');
    viewport = document.getElementById('graph-viewport');
    if (!canvas || !viewport) return;
    ctx = canvas.getContext('2d');
    syncNodes(false);
    resize(true);
    fitView();

    canvas.addEventListener('pointerdown', onPointerDown);
    canvas.addEventListener('pointermove', onPointerMove);
    canvas.addEventListener('pointerup', onPointerUp);
    canvas.addEventListener('pointercancel', onPointerUp);
    canvas.addEventListener('wheel', onWheel, { passive: false });
    canvas.addEventListener('dblclick', onDblClick);

    document.getElementById('graph-zoom-in')?.addEventListener('click', () => {
      zoomAt(1.2, width / 2, height / 2);
    });
    document.getElementById('graph-zoom-out')?.addEventListener('click', () => {
      zoomAt(0.84, width / 2, height / 2);
    });
    document.getElementById('graph-fit')?.addEventListener('click', () => fitView());
    document.getElementById('graph-relayout')?.addEventListener('click', () => relayout());
    document.getElementById('graph-reset-pos')?.addEventListener('click', () => resetPositions());

    document.querySelector('.graph-side-stack')?.addEventListener('click', (e) => {
      const btn = e.target.closest('[data-peer-check]');
      if (!btn) return;
      e.preventDefault();
      e.stopPropagation();
      runGraphPeerQuickCheck(btn.dataset.nodeId, btn.dataset.kind, parseInt(btn.dataset.index, 10));
    });

    window.addEventListener('resize', () => {
      if (active) resize(false);
    });

    if (typeof ResizeObserver !== 'undefined' && viewport) {
      const ro = new ResizeObserver(() => {
        if (active) resize(false);
      });
      ro.observe(viewport);
    }
  }

  let hasInitialLayout = false;

  function activate() {
    active = true;
    syncNodes(true);
    resize(false);
    requestAnimationFrame(() => { if (active) resize(false); });
    if (!hasInitialLayout) {
      relayout();
      hasInitialLayout = true;
    } else {
      alpha = Math.max(alpha, 0.25);
    }
    if (!animId) loop();
  }

  function deactivate() {
    active = false;
    hoveredId = null;
    draggingId = null;
    panning = false;
    selectedId = null;
    graphDetailNodeId = null;
    cameraFollowId = null;
    viewport?.classList.remove('is-panning', 'is-dragging-node');
    if (animId) {
      cancelAnimationFrame(animId);
      animId = null;
    }
    resetGraphSidePanels();
    const panel = document.getElementById('node-detail');
    if (panel) {
      panel.classList.remove('is-active');
      panel.innerHTML = `<div class="graph-detail-placeholder">
        <span class="graph-detail-placeholder-icon" aria-hidden="true">◎</span>
        <h2>Узел не выбран</h2>
        <p class="muted">Кликните узел на графе — карточка откроется здесь</p>
      </div>`;
    }
  }

  function afterDataChange(nearId) {
    syncNodes(true);
    if (nearId) {
      const anchor = getSim(nearId);
      const added = simNodes[simNodes.length - 1];
      if (anchor && added && added.id !== nearId) {
        const angle = Math.random() * Math.PI * 2;
        added.x = anchor.x + Math.cos(angle) * 48;
        added.y = anchor.y + Math.sin(angle) * 48;
      }
    }
    alpha = 1;
    if (active) {
      if (!animId) loop();
      else render();
    }
  }

  function setCase() {
    selectedId = null;
    cameraFollowId = null;
    graphDetailNodeId = null;
    showDetail(null);
    syncNodes(false);
    relayout();
    focusOnCenter(getFocusNodeId());
    pendingLayoutSnapshot = true;
    alpha = 1;
    if (active) {
      if (!animId) loop();
      else render();
    }
  }

  return { init, activate, deactivate, resize, relayout, afterDataChange, setCase, resetPositions, selectNode };
})();

graphView.init();

// --- OSINT Intelligence (demo simulation) ---

const DEMO_CASE_ID = 'ЕПСОК-2028-004521';
let osintScanSeq = 88511;
let selectedOsintScanId = null;

const GRAPH_CASE_ANCHORS = {
  'ЕПСОК-2028-004521': { caseNodeId: 'c1', anchorId: 'p1', short: 'Краснодар' },
  'ЕПСОК-2028-001234': { caseNodeId: 'c2', anchorId: 'acc1', short: 'Москва' },
  'ЕПСОК-2028-002891': { caseNodeId: 'c3', anchorId: 'ph2', short: 'Казань' }
};

function getGraphCasesForPersona() {
  const withGraph = new Set(graphNodes.map(n => n.caseId).filter(Boolean));
  Object.keys(GRAPH_CASE_ANCHORS).forEach(id => withGraph.add(id));
  return getPersonaScopedCases().filter(c => withGraph.has(c.id));
}

function countGraphNodesForCase(caseId) {
  return graphNodes.filter(n => n.caseId === caseId).length;
}

function renderGraphCasePicker() {
  const el = document.getElementById('graph-case-list');
  if (!el) return;
  const cases = getGraphCasesForPersona();
  el.innerHTML = cases.map(c => {
    const nodeCount = countGraphNodesForCase(c.id);
    const place = getCaseRegionShort(c.id);
    const relatedHint = (c.related || []).length
      ? `<span class="graph-case-hint muted">Похожие: ${c.related.map(r => escapeHtml(enrichRelatedEntry(r).place)).join(', ')} — отдельный граф</span>`
      : '';
    return `<button type="button" class="graph-case-card" onclick="selectGraphCase('${c.id}')">
      <span class="graph-case-id">${c.id}</span>
      <span class="graph-case-title">${escapeHtml(place)} · ${escapeHtml(c.article)}</span>
      <span class="graph-case-meta">${escapeHtml(c.region)} · ${escapeHtml(c.department)} · ${nodeCount} узлов</span>
      ${c.cluster ? `<span class="link-badge">${escapeHtml(c.cluster)}</span>` : ''}
      ${relatedHint}
    </button>`;
  }).join('') || '<p class="muted">Нет дел с графом для вашего контура.</p>';
}

function updateGraphCaseHeader() {
  const c = getCaseById(activeGraphCaseId);
  const titleEl = document.getElementById('graph-case-title');
  const subEl = document.getElementById('graph-case-sub');
  if (titleEl) {
    titleEl.textContent = c
      ? `Граф · ${c.id} · ${getCaseRegionShort(c.id)}`
      : `Граф · ${activeGraphCaseId}`;
  }
  if (subEl && c) {
    subEl.textContent = `${c.article} · ${c.agencyName} · ${c.department}${c.cluster ? ` · ${c.cluster}` : ''}`;
  }
}

function selectGraphCase(caseId) {
  if (!personaCanAccessCase(caseId)) {
    showToast('ПОЛ-001: нет доступа к этому делу для текущей роли.');
    return;
  }
  activeGraphCaseId = caseId;
  activeCaseId = caseId;
  updateHeaderContext();
  renderGraphView();
}

function clearGraphCaseSelection() {
  activeGraphCaseId = null;
  graphView.deactivate();
  renderGraphView();
}

function openCaseGraph(caseId) {
  if (!personaCanAccessCase(caseId)) {
    showToast('ПОЛ-001: нет доступа к этому делу для текущей роли.');
    return;
  }
  activeGraphCaseId = caseId;
  activeCaseId = caseId;
  showView('graph', { keepGraphCase: true });
}

function renderGraphView() {
  const picker = document.getElementById('graph-case-picker');
  const caseView = document.getElementById('graph-case-view');
  if (!activeGraphCaseId) {
    picker?.classList.remove('hidden');
    caseView?.classList.add('hidden');
    renderGraphCasePicker();
    graphView.deactivate();
    return;
  }
  picker?.classList.add('hidden');
  caseView?.classList.remove('hidden');
  updateGraphCaseHeader();
  graphView.setCase();
  graphView.activate();
}

const PHONE_SUFFIX_CASE_HINTS = {
  '4567': 'ЕПСОК-2028-004521',
  '8901': 'ЕПСОК-2028-002891',
  '4521': 'ЕПСОК-2028-001234'
};

function graphSourceKey(normalizedType, value) {
  const v = (value || '').toLowerCase().trim();
  if (normalizedType === 'phone') return `phone:${value.replace(/\D/g, '').slice(-4)}`;
  if (normalizedType === 'person_name') return `person:${v.replace(/\s+/g, ' ')}`;
  if (normalizedType === 'username' || normalizedType === 'social_profile') return `social:${v.slice(0, 48)}`;
  if (normalizedType === 'email') return `email:${v}`;
  if (normalizedType === 'domain') return `domain:${v.replace(/^https?:\/\//, '')}`;
  return `${normalizedType}:${v.slice(0, 48)}`;
}

function getGraphCaseAnchor(caseId) {
  const anchor = GRAPH_CASE_ANCHORS[caseId] || GRAPH_CASE_ANCHORS[DEMO_CASE_ID];
  if (!anchor) return null;
  const short = getCaseRegionShort(caseId);
  return short ? { ...anchor, short } : anchor;
}

function getOsintScanCaseId(scan) {
  if (scan?.caseId) return scan.caseId;
  if (activeCaseId && personaCanAccessCase(activeCaseId)) return activeCaseId;
  return DEMO_CASE_ID;
}

function findMatchingGraphNode(finding) {
  const key = graphSourceKey(finding.normalizedType, finding.value);
  const direct = graphNodes.find(n => n.sourceKey === key);
  if (direct) return direct;

  if (finding.normalizedType === 'phone') {
    const suffix = finding.value.replace(/\D/g, '').slice(-4);
    return graphNodes.find(n => {
      if (n.type !== 'phone') return false;
      if (n.sourceKey === `phone:${suffix}`) return true;
      const fromValue = (n.sourceValue || '').replace(/\D/g, '').slice(-4);
      return fromValue === suffix;
    }) || null;
  }

  if (finding.normalizedType === 'social_profile' || finding.normalizedType === 'username') {
    const needle = finding.value.toLowerCase();
    return graphNodes.find(n => (n.type === 'social' || n.type === 'username')
      && ((n.sourceValue || '').toLowerCase().includes(needle.slice(0, 12))
        || needle.includes((n.sourceValue || n.label || '').toLowerCase().slice(0, 12)))) || null;
  }

  return null;
}

function inferCaseForFinding(finding, scan) {
  const matched = findMatchingGraphNode(finding);
  if (matched?.caseId) return matched.caseId;

  if (finding.normalizedType === 'phone') {
    const suffix = finding.value.replace(/\D/g, '').slice(-4);
    if (PHONE_SUFFIX_CASE_HINTS[suffix]) return PHONE_SUFFIX_CASE_HINTS[suffix];
  }

  if (finding.graphNodeId) {
    const linked = graphNodes.find(n => n.id === finding.graphNodeId);
    if (linked?.caseId) return linked.caseId;
  }

  return getOsintScanCaseId(scan);
}

function ensureGraphEdge(a, b) {
  if (!a || !b || a === b) return;
  const exists = graphEdges.some(([s, t]) => (s === a && t === b) || (s === b && t === a));
  if (!exists) graphEdges.push([a, b]);
}

function graphNodeTypeForFinding(normalizedType) {
  if (normalizedType === 'phone') return 'phone';
  if (normalizedType === 'person_name') return 'person';
  if (normalizedType === 'username') return 'username';
  if (normalizedType === 'social_profile') return 'social';
  if (normalizedType === 'domain') return 'org';
  return 'social';
}

function graphLabelForFinding(finding) {
  if (finding.normalizedType === 'phone') {
    return formatPhoneRu(finding.value);
  }
  if (finding.normalizedType === 'person_name') {
    const parts = finding.value.split(' ');
    return `${parts[0]} ${(parts[1]?.[0] || '')}.`;
  }
  return finding.value.length > 22 ? finding.value.slice(0, 20) + '…' : finding.value;
}

function attachFindingToGraph(finding, caseId) {
  const importable = ['phone', 'social_profile', 'username', 'person_name', 'domain'];
  if (!importable.includes(finding.normalizedType)) {
    return { action: 'skipped', nodeId: null, caseId };
  }

  const existing = findMatchingGraphNode(finding);
  if (existing) {
    const anchor = getGraphCaseAnchor(existing.caseId || caseId);
    ensureGraphEdge(anchor.anchorId, existing.id);
    if (anchor.caseNodeId) ensureGraphEdge(existing.id, anchor.caseNodeId);
    finding.graphNodeId = existing.id;
    finding.importCaseId = existing.caseId || caseId;
    return { action: 'linked', nodeId: existing.id, caseId: existing.caseId || caseId };
  }

  const anchor = getGraphCaseAnchor(caseId);
  const nodeId = `osint_${finding.normalizedType}_${finding.id}`;
  const node = {
    id: nodeId,
    type: graphNodeTypeForFinding(finding.normalizedType),
    label: graphLabelForFinding(finding),
    detail: `Открытые источники · ${osintModuleLabel(finding.sourceModule)} · ${caseId}`,
    caseId,
    sourceKey: graphSourceKey(finding.normalizedType, finding.value),
    sourceValue: finding.value,
    osintFindingId: finding.id
  };
  graphNodes.push(node);
  ensureGraphEdge(anchor.anchorId, nodeId);
  if (anchor.caseNodeId) ensureGraphEdge(nodeId, anchor.caseNodeId);
  finding.graphNodeId = nodeId;
  finding.importCaseId = caseId;
  return { action: 'created', nodeId, caseId };
}

function previewOsintImportCases(findings, scan) {
  const map = new Map();
  findings.forEach(f => {
    const caseId = inferCaseForFinding(f, scan);
    const anchor = getGraphCaseAnchor(caseId);
    const matched = findMatchingGraphNode(f);
    if (!map.has(caseId)) map.set(caseId, { caseId, short: anchor.short, created: 0, linked: 0, findings: [] });
    const row = map.get(caseId);
    row.findings.push({
      id: f.id,
      label: f.value,
      type: osintTypeLabels[f.normalizedType] || f.normalizedType,
      mode: matched ? 'объединить' : 'новый узел'
    });
    if (matched) row.linked += 1;
    else row.created += 1;
  });
  return map;
}

function formatCaseShort(caseId) {
  const a = getGraphCaseAnchor(caseId);
  return a ? `${a.short} · ${caseId.slice(-7)}` : caseId;
}

const osintScans = [
  {
    id: 'OSINT-88510',
    caseId: 'ЕПСОК-2028-004521',
    targetType: 'EMAILADDR',
    targetValue: 'suspect.fraud@mail.ru',
    profile: 'footprint_ru',
    status: 'completed',
    findingCount: 7,
    createdAt: '12.06.2028 09:14',
    legalBasis: 'Постановление №142 от 10.06.2028'
  },
  {
    id: 'OSINT-88511',
    caseId: 'ЕПСОК-2028-002891',
    targetType: 'PHONE_NUMBER',
    targetValue: '+79009878901',
    profile: 'footprint_ru',
    status: 'completed',
    findingCount: 3,
    createdAt: '11.06.2028 16:40',
    legalBasis: 'Постановление №138 от 09.06.2028'
  }
];

const osintFindingsByScan = {
  'OSINT-88510': [
    { id: 'f1', normalizedType: 'email', value: 'suspect.fraud@mail.ru', sourceModule: 'sfp_email', confidence: 100, requiresReview: false, reviewStatus: null, importedToGraph: true, sourceTier: 'open' },
    { id: 'f2', normalizedType: 'phone', value: '+79001234567', sourceModule: 'sfp_gravatar', confidence: 85, requiresReview: false, reviewStatus: null, importedToGraph: true, graphNodeId: 'ph1', importCaseId: 'ЕПСОК-2028-004521', sourceTier: 'semi' },
    { id: 'f3', normalizedType: 'phone', value: '+79009878901', sourceModule: 'sfp_phone', confidence: 72, requiresReview: false, reviewStatus: null, importedToGraph: false, sourceTier: 'open' },
    { id: 'f4', normalizedType: 'username', value: 'suspect_fraud_2028', sourceModule: 'sfp_accounts', confidence: 90, requiresReview: false, reviewStatus: null, importedToGraph: false, sourceTier: 'open' },
    { id: 'f5', normalizedType: 'social_profile', value: 'Telegram: @suspect_fraud_2028', sourceModule: 'sfp_accounts', confidence: 88, requiresReview: false, reviewStatus: null, importedToGraph: false, sourceTier: 'open' },
    { id: 'f6', normalizedType: 'social_profile', value: 'VK: vk.com/id123456789', sourceModule: 'sfp_accounts', confidence: 80, requiresReview: false, reviewStatus: null, importedToGraph: false, sourceTier: 'open' },
    { id: 'f7', normalizedType: 'person_name', value: 'Алексей Петров', sourceModule: 'sfp_names', confidence: 68, requiresReview: true, reviewStatus: 'pending', importedToGraph: false, sourceTier: 'semi' }
  ],
  'OSINT-88511': [
    { id: 'k1', normalizedType: 'phone', value: '+79009878901', sourceModule: 'sfp_phone', confidence: 100, requiresReview: false, reviewStatus: null, importedToGraph: false, sourceTier: 'open' },
    { id: 'k2', normalizedType: 'username', value: 'kazan_sim_8901', sourceModule: 'sfp_accounts', confidence: 84, requiresReview: false, reviewStatus: null, importedToGraph: false, sourceTier: 'open' },
    { id: 'k3', normalizedType: 'social_profile', value: 'Telegram: @kazan_sim', sourceModule: 'sfp_accounts', confidence: 76, requiresReview: false, reviewStatus: null, importedToGraph: false, sourceTier: 'open' }
  ]
};

const osintTypeLabels = {
  person_name: 'ФИО',
  email: 'Почта',
  phone: 'Телефон',
  username: 'Никнейм',
  social_profile: 'Соцсеть',
  external_account: 'Аккаунт',
  domain: 'Домен',
  ip: 'IP',
  inn: 'ИНН',
  org: 'Организация',
  vehicle: 'ТС',
  crypto: 'Кошелёк',
  raw_enrichment: 'Обогащение',
  breach_indicator: 'Индикатор утечки',
  smev_hint: 'SMEV-подсказка'
};

function getOsintProfilesForTier(tier = getOsintTier()) {
  return Object.entries(OSINT_PROFILES)
    .filter(([, cfg]) => cfg.tiers.includes(tier))
    .map(([id, cfg]) => ({ id, ...cfg }));
}

function getOsintStats() {
  const caseId = activeCaseId;
  const scansForCase = osintScans.filter(s => getOsintScanCaseId(s) === caseId);
  let findingsCount = 0;
  let pendingReview = 0;
  osintScans.forEach(s => {
    (osintFindingsByScan[s.id] || []).forEach(f => {
      if (!caseId || getOsintScanCaseId(s) === caseId) {
        findingsCount += 1;
        if (f.requiresReview && f.reviewStatus === 'pending') pendingReview += 1;
      }
    });
  });
  const running = osintScans.filter(s => s.status === 'running' || s.status === 'queued').length;
  const packages = evidencePackages.filter(p => !caseId || p.caseId === caseId).length;
  return {
    scansTotal: osintScans.length,
    scansCase: scansForCase.length,
    findingsCount,
    pendingReview,
    running,
    packages
  };
}

function renderOsintStats() {
  const el = document.getElementById('osint-kpi-strip');
  if (!el) return;
  const st = getOsintStats();
  el.innerHTML = `
    <div class="osint-kpi"><span class="osint-kpi-val">${st.scansCase}</span><span class="osint-kpi-label">проверок по делу</span></div>
    <div class="osint-kpi"><span class="osint-kpi-val">${st.findingsCount}</span><span class="osint-kpi-label">находок</span></div>
    <div class="osint-kpi${st.pendingReview ? ' osint-kpi-warn' : ''}"><span class="osint-kpi-val">${st.pendingReview}</span><span class="osint-kpi-label">на проверке</span></div>
    <div class="osint-kpi"><span class="osint-kpi-val">${st.packages}</span><span class="osint-kpi-label">пакетов</span></div>`;
}

const OSINT_TARGET_CHIPS = [
  { type: 'EMAILADDR', label: 'Почта', icon: '@' },
  { type: 'PHONE_NUMBER', label: 'Телефон', icon: '☎' },
  { type: 'USERNAME', label: 'Ник', icon: '◦' },
  { type: 'HUMAN_NAME', label: 'ФИО', icon: '👤' },
  { type: 'INN_OGRN', label: 'ИНН', icon: '§' },
  { type: 'IP_ADDRESS', label: 'IP', icon: '⌁' }
];

function renderOsintTargetChips() {
  const el = document.getElementById('osint-target-chips');
  const sel = document.getElementById('osint-target-type');
  if (!el || !sel) return;
  const current = sel.value;
  el.innerHTML = OSINT_TARGET_CHIPS.map(c =>
    `<button type="button" class="osint-target-chip${c.type === current ? ' active' : ''}" onclick="setOsintTargetType('${c.type}')"><span class="osint-target-chip-icon" aria-hidden="true">${c.icon}</span>${c.label}</button>`
  ).join('');
}

function setOsintTargetType(type) {
  const sel = document.getElementById('osint-target-type');
  if (sel) sel.value = type;
  onOsintTargetTypeChange();
  renderOsintTargetChips();
}

function renderOsintConfidence(pct) {
  const cls = pct >= 85 ? 'high' : pct >= 60 ? 'mid' : 'low';
  return `<div class="osint-conf" title="Уверенность ${pct}%"><div class="osint-conf-track"><div class="osint-conf-bar ${cls}" style="width:${pct}%"></div></div><span class="osint-conf-val">${pct}%</span></div>`;
}

function osintTypeTagClass(type) {
  const m = { email: 'tag-email', phone: 'tag-phone', username: 'tag-user', person_name: 'tag-person', social_profile: 'tag-social', domain: 'tag-domain', ip: 'tag-ip', inn: 'tag-gov', org: 'tag-gov', smev_hint: 'tag-smev' };
  return m[type] || 'tag-default';
}

function getVisibleOsintScans() {
  const filterCase = document.getElementById('osint-filter-case')?.checked !== false;
  const list = filterCase && activeCaseId
    ? osintScans.filter(s => getOsintScanCaseId(s) === activeCaseId)
    : osintScans.slice();
  return list.sort((a, b) => {
    const ac = getOsintScanCaseId(a) === activeCaseId ? 0 : 1;
    const bc = getOsintScanCaseId(b) === activeCaseId ? 0 : 1;
    if (ac !== bc) return ac - bc;
    return b.id.localeCompare(a.id);
  });
}

function ensureOsintScanSelected() {
  if (selectedOsintScanId && osintScans.some(s => s.id === selectedOsintScanId)) return;
  const visible = getVisibleOsintScans();
  if (visible[0]) selectOsintScan(visible[0].id);
  else {
    selectedOsintScanId = null;
    const panel = document.getElementById('osint-findings-panel');
    if (panel) panel.hidden = true;
  }
}

function renderOsintPage() {
  const tier = getOsintTier();
  const p = getActivePersona();
  const c = getCaseById(activeCaseId);
  const heroCase = document.getElementById('osint-hero-case');
  const heroSub = document.getElementById('osint-hero-sub');
  if (heroCase) heroCase.textContent = c?.id || activeCaseId || '—';
  if (heroSub) {
    heroSub.textContent = c
      ? `${p.headerContour || 'Следственный контур'} · ${c.region} · ${c.department}`
      : `${p.headerContour || 'Следственный контур'} · выберите дело для привязки проверки`;
  }
  renderOsintStats();
  const capEl = document.getElementById('osint-capabilities');
  if (capEl) {
    const profiles = getOsintProfilesForTier(tier);
    const tierLabel = {
      investigator: 'Следственный контур',
      operative: 'Оперативный контур',
      supervisory: 'Надзорный контур',
      readonly: 'Только просмотр'
    }[tier] || '—';
    capEl.innerHTML = `
      <div class="osint-cap-head">
        <div>
          <strong class="osint-cap-title">${tierLabel}</strong>
          <p class="muted osint-cap-sub">Возможности выше, чем у гражданских сервисов «пробива» · все действия в WORM-аудите</p>
        </div>
        <span class="osint-cap-pill">${profiles.length} профил${profiles.length === 1 ? 'ь' : profiles.length < 5 ? 'я' : 'ей'}</span>
      </div>
      <div class="osint-cap-grid">
        <div class="osint-cap-card">
          <span class="osint-cap-card-label">Гражданский OSINT</span>
          <ul class="osint-cap-list muted"><li>1–2 открытых источника</li><li>Без правового основания</li><li>Нет связи с делом</li></ul>
        </div>
        <div class="osint-cap-card osint-cap-card-gov">
          <span class="osint-cap-card-label">ЕПСОК · ${escapeHtml(tierLabel)}</span>
          <ul class="osint-cap-list"><li>До ${tier === 'investigator' ? '40+' : '15+'} модулей whitelist</li><li>SMEV / реестры / архивы</li><li>Привязка к делу и графу</li><li>Пакеты доказательств</li></ul>
        </div>
      </div>`;
  }

  const caseSel = document.getElementById('osint-case-select');
  if (caseSel) {
    const cases = getPersonaScopedCases();
    caseSel.innerHTML = cases.map(c =>
      `<option value="${c.id}"${c.id === activeCaseId ? ' selected' : ''}>${escapeHtml(c.id)} · ${escapeHtml(getCaseRegionShort(c.id))}</option>`
    ).join('');
    if (!cases.some(c => c.id === activeCaseId) && cases[0]) activeCaseId = cases[0].id;
  }

  const profileSel = document.getElementById('osint-profile');
  if (profileSel) {
    const prev = profileSel.value;
    const profiles = getOsintProfilesForTier(tier);
    profileSel.innerHTML = profiles.map(pr =>
      `<option value="${pr.id}">${escapeHtml(pr.label)}</option>`
    ).join('');
    if (profiles.some(pr => pr.id === prev)) profileSel.value = prev;
    else if (profiles.some(pr => pr.id === 'footprint_ru')) profileSel.value = 'footprint_ru';
    profileSel.dispatchEvent(new Event('change'));
  }

  const advWrap = document.getElementById('osint-advanced-wrap');
  if (advWrap) {
    advWrap.classList.toggle('hidden', !canLaunchOsintScan());
    advWrap.querySelectorAll('input').forEach(el => { el.disabled = !canLaunchOsintScan(); });
  }

  syncCapabilityButtons(p);
  onOsintTargetTypeChange();
  renderOsintTargetChips();
}

function renderOsintProfileModules() {
  const profile = document.getElementById('osint-profile')?.value;
  const el = document.getElementById('osint-profile-modules');
  if (!el || !profile) return;
  const cfg = OSINT_PROFILES[profile];
  if (!cfg) { el.innerHTML = ''; return; }
  el.innerHTML = cfg.modules.map(m =>
    `<span class="osint-module-pill">${escapeHtml(osintModuleLabel(m))}</span>`
  ).join('');
}

function setOsintCase(caseId) {
  activeCaseId = caseId;
  updateHeaderContext();
  renderOsintPage();
  renderOsintScans();
  ensureOsintScanSelected();
}

function osintTargetPlaceholder(type) {
  const m = {
    EMAILADDR: 'podozrevaemyj@mail.ru',
    PHONE_NUMBER: '+7 900 123-45-67',
    USERNAME: 'suspect_fraud_2028',
    HUMAN_NAME: 'Андреев Сергей Викторович',
    INTERNET_NAME: 'example-shop.ru',
    IP_ADDRESS: '185.22.60.14',
    INN_OGRN: '2310011223 / 1234567890123',
    VEHICLE_PLATE: 'К123АВ123',
    CRYPTO_WALLET: 'TXyz… (TRC-20)',
    SOCIAL_ID: 'vk.com/id123456789'
  };
  return m[type] || '';
}

function onOsintTargetTypeChange() {
  const type = document.getElementById('osint-target-type')?.value;
  const input = document.getElementById('osint-target-value');
  if (input && type) input.placeholder = osintTargetPlaceholder(type);
  renderOsintTargetChips();
}

function maskTarget(type, value) {
  if (type === 'EMAILADDR' && value.includes('@')) {
    const [u, d] = value.split('@');
    return `${u.slice(0, 2)}***@${d}`;
  }
  if (type === 'PHONE_NUMBER') return value.slice(0, 4) + ' *** ** ' + value.slice(-2);
  return value.length > 12 ? value.slice(0, 8) + '…' : value;
}

function renderOsintScans() {
  const el = document.getElementById('osint-scans-list');
  const sub = document.getElementById('osint-scans-sub');
  if (!el) return;
  const visible = getVisibleOsintScans();
  if (sub) {
    sub.textContent = visible.length
      ? `${visible.length} из ${osintScans.length} · ${formatCaseShort(activeCaseId || DEMO_CASE_ID)}`
      : osintScans.length ? 'Нет проверок по выбранному делу' : 'Запустите первую проверку слева';
  }
  renderOsintStats();
  if (!visible.length) {
    el.innerHTML = `<div class="osint-empty"><span class="osint-empty-icon" aria-hidden="true">⌕</span><p class="muted">${osintScans.length ? 'Снимите фильтр «Только по делу» или выберите другое дело' : 'Проверок пока нет'}</p></div>`;
  } else {
    el.innerHTML = visible.map(s => {
      const isActive = selectedOsintScanId === s.id;
      const isRunning = s.status === 'running' || s.status === 'queued';
      const targetLabel = osintTargetTypeLabels[s.targetType] || s.targetType;
      return `
    <button type="button" class="osint-scan-card${isActive ? ' active' : ''}${isRunning ? ' running' : ''}"
      onclick="selectOsintScan('${s.id}')">
      <div class="osint-scan-head">
        <span class="osint-scan-glyph" aria-hidden="true">⌕</span>
        <div class="osint-scan-head-text">
          <span class="osint-scan-id">${formatScanId(s.id)}</span>
          <span class="osint-scan-target">${targetLabel}: ${maskTarget(s.targetType, s.targetValue)}</span>
        </div>
        <span class="status osint-status ${s.status}">${osintStatusLabel(s.status)}</span>
      </div>
      <div class="osint-scan-tags">
        <span class="osint-tag">${osintProfileLabels[s.profile] || s.profile}</span>
        <span class="osint-tag osint-tag-case">${formatCaseShort(getOsintScanCaseId(s))}</span>
      </div>
      ${isRunning ? '<div class="osint-scan-progress" aria-hidden="true"><span class="osint-scan-progress-bar"></span></div>' : ''}
      <div class="osint-scan-foot">
        <span>${s.createdAt}</span>
        <span class="osint-scan-findings">${s.findingCount} находок</span>
      </div>
    </button>`;
    }).join('');
  }
  renderEvidencePackages();
}

function osintStatusLabel(status) {
  const m = { queued: 'В очереди', running: 'Выполняется…', completed: 'Завершён', failed: 'Ошибка', cancelled: 'Отменён' };
  return m[status] || status;
}

function selectOsintScan(scanId) {
  selectedOsintScanId = scanId;
  resetTablePage('osint-findings');
  renderOsintScans();
  renderOsintFindings(scanId);
}

function renderOsintFindings(scanId) {
  tablePageRefresh['osint-findings'] = () => renderOsintFindings(scanId);
  const panel = document.getElementById('osint-findings-panel');
  const body = document.getElementById('osint-findings-body');
  const title = document.getElementById('osint-findings-title');
  const findings = osintFindingsByScan[scanId] || [];

  if (!panel || !body) return;
  panel.hidden = false;
  const scan = osintScans.find(s => s.id === scanId);
  title.textContent = `Находки · ${formatScanId(scanId)}`;
  const sub = document.getElementById('osint-findings-sub');
  if (sub && scan) {
    sub.textContent = `${osintTargetTypeLabels[scan.targetType] || scan.targetType}: ${maskTarget(scan.targetType, scan.targetValue)} · ${osintProfileLabels[scan.profile] || scan.profile}`;
  }
  renderOsintStats();

  if (!findings.length) {
    body.innerHTML = `<tr><td colspan="8" class="muted" style="text-align:center;padding:1.5rem">Нет находок</td></tr>`;
    mountTablePagination('osint-findings-pagination', { total: 0, pageSize: TABLE_PAGE_SIZE, key: 'osint-findings' });
    return;
  }

  const meta = paginateList(findings, 'osint-findings');
  body.innerHTML = meta.slice.map(f => {
    const scan = osintScans.find(s => s.id === scanId);
    const targetCase = inferCaseForFinding(f, scan);
    const matched = findMatchingGraphNode(f);
    const targetHint = matched
      ? `<span class="link-badge">объединить · ${formatCaseShort(matched.caseId || targetCase)}</span>`
      : `<span class="muted">${formatCaseShort(targetCase)}</span>`;
    const tierBadge = f.sourceTier
      ? `<span class="osint-tier-badge osint-tier-${f.sourceTier}">${osintSourceTierLabels[f.sourceTier] || f.sourceTier}</span> `
      : '';
    const deepenBtn = canLaunchOsintScan() && !f.importedToGraph
      ? `<button type="button" class="btn-xs" onclick="expandOsintFromFinding('${f.id}')" title="Цепочная проверка">↻</button>`
      : '';
    return `
    <tr class="osint-finding-row${f.importedToGraph ? ' row-imported' : ''}">
      <td><input type="checkbox" class="osint-finding-cb" data-id="${f.id}" ${f.importedToGraph ? 'disabled' : 'checked'}></td>
      <td><span class="type-tag ${osintTypeTagClass(f.normalizedType)}">${osintTypeLabels[f.normalizedType] || f.normalizedType}</span></td>
      <td class="mono osint-finding-value">${escapeHtml(f.value)}</td>
      <td class="osint-finding-source muted">${tierBadge}${osintModuleLabel(f.sourceModule)}</td>
      <td>${renderOsintConfidence(f.confidence)}</td>
      <td>${renderReviewCell(f)}</td>
      <td>${targetHint}</td>
      <td class="osint-finding-actions">${f.importedToGraph ? '<span class="link-badge">в графе</span>' : deepenBtn}</td>
    </tr>`;
  }).join('');
  mountTablePagination('osint-findings-pagination', meta);
}

function renderReviewCell(f) {
  if (!f.requiresReview) return '—';
  if (f.reviewStatus === 'pending') {
    return `<button type="button" class="btn-xs approve" onclick="reviewFinding('${selectedOsintScanId}','${f.id}','approved')">✓</button>
            <button type="button" class="btn-xs reject" onclick="reviewFinding('${selectedOsintScanId}','${f.id}','rejected')">✗</button>`;
  }
  if (f.reviewStatus === 'approved') return '<span class="status fulfilled">Подтв.</span>';
  return '<span class="status rejected">Отклонено</span>';
}

function escapeHtml(s) {
  if (typeof EpsokSecurity !== 'undefined') return EpsokSecurity.escapeHtml(s);
  if (s == null) return '';
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function updateSecurityStrip() {
  const el = document.getElementById('security-strip');
  if (!el) return;
  const loggedIn = document.documentElement.dataset.auth === 'app';
  const techAdmin = isTechAdminPersona();
  el.hidden = !loggedIn || !techAdmin;
  if (loggedIn && techAdmin) {
    el.innerHTML = '<span class="sec-pill sec-pill-gost">ГОСТ TLS 1.3</span><span class="sec-pill">AES-256-GCM</span><span class="sec-pill">HMAC-SHA-256</span><span class="sec-pill">WORM-аудит</span><span class="sec-pill sec-pill-ok">Контур активен</span>';
  }
}

function submitOsintScan(e) {
  e.preventDefault();
  if (!canLaunchOsintScan()) {
    showToast('ПОЛ-006: запуск проверок недоступен для вашей роли.');
    return;
  }
  const targetType = document.getElementById('osint-target-type').value;
  const targetValue = document.getElementById('osint-target-value').value.trim();
  const profile = document.getElementById('osint-profile').value;
  const legalBasis = document.getElementById('osint-legal-basis').value.trim();
  const caseId = document.getElementById('osint-case-select')?.value || activeCaseId;
  const opts = {
    crossRef: document.getElementById('osint-opt-cross')?.checked,
    archive: document.getElementById('osint-opt-archive')?.checked,
    leakIndex: document.getElementById('osint-opt-leak')?.checked
  };

  if (legalBasis.length < 10) {
    showToast('Укажите правовое основание (ПОЛ-006).');
    return;
  }
  if (caseId) activeCaseId = caseId;

  osintScanSeq += 1;
  const scanId = `OSINT-${osintScanSeq}`;
  const scan = {
    id: scanId,
    caseId: caseId || getOsintScanCaseId(),
    targetType,
    targetValue,
    profile,
    status: 'queued',
    findingCount: 0,
    createdAt: new Date().toLocaleString('ru-RU'),
    legalBasis,
    options: opts
  };
  osintScans.unshift(scan);
  renderOsintScans();
  document.getElementById('osint-submit-btn').disabled = true;
  const profLabel = osintProfileLabels[profile] || profile;
  showToast(`Проверка ${formatScanId(scanId)} · ${profLabel} · постановка в очередь…`);

  setTimeout(() => {
    scan.status = 'running';
    renderOsintScans();
  }, 800);

  const duration = (OSINT_PROFILES[profile]?.depth || 2) * 900 + 1400;
  setTimeout(() => {
    const findings = generateMockFindings(targetType, targetValue, profile, opts);
    osintFindingsByScan[scanId] = findings;
    scan.status = 'completed';
    scan.findingCount = findings.length;
    renderOsintScans();
    selectOsintScan(scanId);
    document.getElementById('osint-submit-btn').disabled = false;
    showToast(`Проверка ${formatScanId(scanId)} завершена: ${findings.length} находок.`);
  }, duration);
}

function expandOsintFromFinding(findingId) {
  if (!canLaunchOsintScan()) return;
  const findings = osintFindingsByScan[selectedOsintScanId] || [];
  const f = findings.find(x => x.id === findingId);
  if (!f) return;
  const typeMap = {
    email: 'EMAILADDR',
    phone: 'PHONE_NUMBER',
    username: 'USERNAME',
    person_name: 'HUMAN_NAME',
    domain: 'INTERNET_NAME',
    ip: 'IP_ADDRESS',
    inn: 'INN_OGRN',
    org: 'INN_OGRN',
    social_profile: 'SOCIAL_ID'
  };
  const targetType = typeMap[f.normalizedType] || 'USERNAME';
  document.getElementById('osint-target-type').value = targetType;
  document.getElementById('osint-target-value').value = f.value.replace(/^(VK:|Telegram:|Instagram:|GitHub:)\s*/i, '').trim();
  onOsintTargetTypeChange();
  if (document.getElementById('osint-profile')) {
    document.getElementById('osint-profile').value = 'investigate_ru';
    renderOsintProfileModules();
  }
  document.getElementById('osint-form')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  showToast('Цепочная проверка: значение подставлено в форму');
}

function generateMockFindings(targetType, targetValue, profile = 'footprint_ru', opts = {}) {
  const findings = [];
  let n = 0;
  const depth = OSINT_PROFILES[profile]?.depth || 2;
  const add = (normalizedType, value, sourceModule, confidence, requiresReview = false, sourceTier = 'open') => {
    n += 1;
    findings.push({
      id: `f${n}-${Date.now()}`,
      normalizedType,
      value,
      sourceModule,
      confidence,
      requiresReview,
      reviewStatus: requiresReview ? 'pending' : null,
      importedToGraph: false,
      sourceTier
    });
  };

  if (targetType === 'EMAILADDR') {
    add('email', targetValue, 'sfp_email', 100);
    add('phone', '+7 (918) 521-21-88', 'sfp_gravatar', 82);
    add('username', targetValue.split('@')[0], 'sfp_gravatar', 88);
    add('social_profile', 'VK: vk.com/' + targetValue.split('@')[0], 'sfp_accounts', 75);
    add('person_name', 'Иван ' + targetValue.split('@')[0].split('.')[0], 'sfp_names', 65, true);
    if (depth >= 2) {
      add('social_profile', 'Telegram: @' + targetValue.split('@')[0], 'sfp_accounts', 72);
      add('domain', targetValue.split('@')[1], 'sfp_whois', 90, false, 'semi');
    }
    if (depth >= 3) {
      add('external_account', 'Avito: профиль продавца', 'sfp_spider', 68);
      add('ip', '185.22.60.14', 'sfp_dnsresolve', 55, false, 'semi');
    }
  } else if (targetType === 'PHONE_NUMBER') {
    add('phone', targetValue, 'sfp_phone', 100);
    add('username', 'user_' + targetValue.replace(/\D/g, '').slice(-4), 'sfp_accounts', 70);
    add('social_profile', 'Telegram: найден профиль', 'sfp_accounts', 72);
    if (depth >= 2) add('person_name', 'Кузнецова Т.В.', 'gov_fssp_public', 58, true, 'gov');
    if (depth >= 3) add('raw_enrichment', 'Оператор МТС · номинал · 847 исх./30 дн.', 'gov_smev_hint', 80, false, 'smev');
  } else if (targetType === 'USERNAME') {
    add('username', targetValue, 'sfp_accounts', 100);
    add('social_profile', 'Instagram: @' + targetValue, 'sfp_accounts', 85);
    add('social_profile', 'GitHub: ' + targetValue, 'sfp_keybase', 90);
    if (depth >= 2) add('email', targetValue + '@mail.ru', 'sfp_email', 62);
  } else if (targetType === 'HUMAN_NAME') {
    add('person_name', targetValue, 'sfp_names', 78, true);
    add('social_profile', 'LinkedIn: профиль (поиск)', 'sfp_social', 60);
    if (depth >= 3) add('inn', '2310011223', 'gov_egrul', 72, false, 'gov');
  } else if (targetType === 'INN_OGRN') {
    const inn = targetValue.replace(/\D/g, '').slice(0, 10);
    add('inn', inn || targetValue, 'gov_egrul', 100, false, 'gov');
    add('org', 'ООО «Номинал-Сервис»', 'gov_egrul', 95, false, 'gov');
    add('person_name', 'Директор: Петров С.А.', 'gov_egrul', 88, true, 'gov');
    add('phone', '+7 (861) 422-33-44', 'sfp_phone', 70);
  } else if (targetType === 'IP_ADDRESS') {
    add('ip', targetValue, 'sfp_dnsresolve', 100);
    add('domain', 'host.example.net', 'sfp_whois', 85, false, 'semi');
    if (depth >= 2) add('raw_enrichment', 'ASN: Rostelecom · Краснодар', 'sfp_webanalyze', 78, false, 'semi');
  } else if (targetType === 'VEHICLE_PLATE') {
    add('vehicle', targetValue.toUpperCase(), 'gov_gibdd_public', 92, false, 'gov');
    add('person_name', 'Владелец (открытый контур)', 'gov_gibdd_public', 70, true, 'gov');
  } else if (targetType === 'CRYPTO_WALLET') {
    add('crypto', targetValue, 'sfp_blockchain', 100);
    add('raw_enrichment', '3 входящих транзакции · биржа', 'sfp_blockchain', 75, false, 'semi');
  } else if (targetType === 'SOCIAL_ID') {
    add('social_profile', targetValue, 'sfp_accounts', 100);
    add('username', targetValue.split('/').pop(), 'sfp_accounts', 88);
  } else {
    add('domain', targetValue, 'sfp_whois', 100);
    add('email', 'info@' + targetValue.replace(/^https?:\/\//, ''), 'sfp_spider', 80);
    add('phone', '+7 (495) 123-45-67', 'sfp_phone', 70);
    if (depth >= 2) add('org', 'ООО «' + targetValue.split('.')[0] + '»', 'gov_egrul', 82, false, 'gov');
  }

  if (opts.archive && depth >= 2) {
    add('raw_enrichment', 'Web Archive: 4 снимка 2023–2025', 'gov_archive', 85, false, 'semi');
  }
  if (opts.crossRef && depth >= 3) {
    add('smev_hint', 'Пересечение с делом ЕПСОК-2028-001234 (счёт)', 'gov_smev_hint', 91, false, 'smev');
  }
  if (opts.leakIndex && depth >= 3) {
    add('breach_indicator', 'Email в индексе утечек 2024 (хеш)', 'gov_leak_index', 76, false, 'gov');
  }
  if (profile === 'gov_federal_ru') {
    add('smev_hint', 'Совпадение SIM с регионом Татарстан', 'gov_smev_hint', 84, false, 'smev');
  }

  return findings;
}

function reviewFinding(scanId, findingId, decision) {
  const findings = osintFindingsByScan[scanId];
  const f = findings?.find(x => x.id === findingId);
  if (!f) return;
  f.reviewStatus = decision;
  renderOsintFindings(scanId);
  showToast(decision === 'approved' ? 'Находка подтверждена — доступна для импорта.' : 'Находка отклонена.');
}

function toggleAllFindings(checked) {
  document.querySelectorAll('.osint-finding-cb:not(:disabled)').forEach(cb => { cb.checked = checked; });
}

function getSelectedFindings() {
  const findings = osintFindingsByScan[selectedOsintScanId] || [];
  const ids = [...document.querySelectorAll('.osint-finding-cb:checked')].map(cb => cb.dataset.id);
  return findings.filter(f => ids.includes(f.id) && !f.importedToGraph && (!f.requiresReview || f.reviewStatus === 'approved'));
}

let pendingOsintImport = null;

function importOsintToGraph() {
  if (!canLaunchOsintScan() || !canAccessView('graph')) {
    showToast('Импорт в граф недоступен для вашей роли.');
    return;
  }
  const toImport = getSelectedFindings();
  if (toImport.length === 0) {
    showToast('Выберите находки для импорта (подтвердите ФИО при необходимости).');
    return;
  }
  const scan = osintScans.find(s => s.id === selectedOsintScanId);
  pendingOsintImport = { findings: toImport, scan };
  openOsintImportModal(toImport, scan);
}

function openOsintImportModal(findings, scan) {
  const modal = document.getElementById('osint-import-modal');
  const preview = document.getElementById('osint-import-preview');
  const caseSelect = document.getElementById('osint-import-case');
  if (!modal || !preview || !caseSelect) return;

  const plan = previewOsintImportCases(findings, scan);
  const caseIds = [...plan.keys()];
  const defaultCase = getOsintScanCaseId(scan);

  caseSelect.innerHTML = `<option value="auto">Авто — разделить по делам</option>
    ${caseIds.map(id => `<option value="${id}">Все в дело: ${formatCaseShort(id)}</option>`).join('')}`;
  caseSelect.value = caseIds.length > 1 ? 'auto' : (caseIds[0] || defaultCase);

  preview.innerHTML = [...plan.values()].map(group => `
    <div class="osint-import-group">
      <div class="osint-import-group-head">
        <strong>${escapeHtml(group.short)}</strong>
        <span class="muted">${group.created ? `+${group.created} новых` : ''}${group.created && group.linked ? ' · ' : ''}${group.linked ? `${group.linked} объединить` : ''}</span>
      </div>
      <ul class="osint-import-list">
        ${group.findings.map(f => `<li><span class="muted">${escapeHtml(f.type)}</span> ${escapeHtml(f.label)} <em>→ ${f.mode}</em></li>`).join('')}
      </ul>
    </div>`).join('');

  modal.classList.remove('hidden');
}

function closeOsintImportModal() {
  document.getElementById('osint-import-modal')?.classList.add('hidden');
  pendingOsintImport = null;
}

function confirmOsintImport() {
  if (!pendingOsintImport) return;
  const mode = document.getElementById('osint-import-case')?.value || 'auto';
  const { findings, scan } = pendingOsintImport;
  const stats = { created: 0, linked: 0, skipped: 0, byCase: {} };
  let focusNode = null;

  findings.forEach(f => {
    const caseId = mode === 'auto' ? inferCaseForFinding(f, scan) : mode;
    const result = attachFindingToGraph(f, caseId);
    if (result.action === 'created') {
      stats.created += 1;
      f.importedToGraph = true;
      focusNode = result.nodeId;
    } else if (result.action === 'linked') {
      stats.linked += 1;
      f.importedToGraph = true;
      focusNode = result.nodeId;
    } else {
      stats.skipped += 1;
    }
    if (result.caseId) stats.byCase[result.caseId] = (stats.byCase[result.caseId] || 0) + 1;
  });

  const anchor = getGraphCaseAnchor(Object.keys(stats.byCase)[0] || getOsintScanCaseId(scan));
  graphView.afterDataChange(focusNode || anchor.anchorId);
  renderOsintFindings(selectedOsintScanId);
  closeOsintImportModal();

  if (!stats.created && !stats.linked) {
    showToast('Выбранные типы (почта и др.) не добавляются в граф напрямую.');
    return;
  }

  const parts = Object.entries(stats.byCase).map(([id, n]) => `${formatCaseShort(id)} (${n})`);
  const actionMsg = [
    stats.created ? `${stats.created} новых` : '',
    stats.linked ? `${stats.linked} объединено` : ''
  ].filter(Boolean).join(', ');
  Object.keys(stats.byCase).forEach(cid => {
    const c = getCaseById(cid);
    if (c) syncGraphFromCase(c);
  });
  showToast(`Импорт в граф: ${actionMsg || 'готово'}. ${parts.join(' · ')}`);
}

async function createOsintEvidence() {
  if (!canCreateEvidencePackage()) {
    showToast('Формирование пакетов доказательств доступно следственному контуру.');
    return;
  }
  const toImport = getSelectedFindings();
  if (toImport.length === 0) {
    showToast('Выберите находки для пакета доказательств.');
    return;
  }
  const scan = osintScans.find(s => s.id === selectedOsintScanId);
  let caseId = scan ? getOsintScanCaseId(scan) : activeCaseId;
  if (!caseId || !getCaseById(caseId)) {
    caseId = getPersonaScopedCases()[0]?.id || DEMO_CASE_ID;
  }
  if (!personaCanAccessCase(caseId)) {
    showToast('Нет доступа к делу для формирования пакета доказательств.');
    return;
  }
  const pkgId = `ДОК-${Date.now().toString().slice(-6)}`;
  const createdAt = new Date().toLocaleString('ru-RU');
  const findings = toImport.map(f => ({ type: f.normalizedType, value: f.value, confidence: f.confidence }));
  const hash = await computeEvidencePackageHash({ id: pkgId, caseId, scanId: selectedOsintScanId, findings, createdAt });
  const pkg = {
    id: pkgId,
    caseId,
    scanId: selectedOsintScanId,
    findings,
    hash,
    createdAt,
    createdBy: getActivePersona().name,
    status: 'sealed'
  };
  expandedEvidenceCaseGroups.add(caseId);
  evidencePackages.unshift(pkg);
  saveEvidencePackages();
  appendCaseTimelineEntry(caseId, `Сформирован пакет доказательств · ${pkg.id}`, { osint: true });
  renderEvidencePackages();
  showToast(`${pkg.id} создан · ${toImport.length} находок · дело ${caseId}`);
  document.getElementById('evidence-packages-panel')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

const EVIDENCE_STORAGE_KEY = 'epsok-evidence-packages';
const EVIDENCE_HASH_HINT = 'Контрольная сумма SHA-256 для проверки целостности файла пакета доказательств';
let evidencePackages = [];
const expandedEvidenceCaseGroups = new Set();

async function computeEvidencePackageHash(core) {
  const payload = JSON.stringify({
    id: core.id,
    caseId: core.caseId,
    scanId: core.scanId,
    findings: core.findings,
    createdAt: core.createdAt
  });
  const bytes = await mailSha256(payload);
  return [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
}

function parseEvidenceHashHex(raw) {
  if (!raw) return '';
  let hex = String(raw).trim().toLowerCase();
  if (hex.startsWith('sha256:')) hex = hex.slice(7);
  hex = hex.replace(/…+$|\.\.\.$/, '').replace(/[^0-9a-f]/g, '');
  return hex;
}

function repairEvidencePackageHash(pkg) {
  const hex = parseEvidenceHashHex(pkg.hash);
  if (hex.length === 64) {
    if (pkg.hash !== hex) {
      pkg.hash = hex;
      return true;
    }
    return false;
  }
  let seed = hex;
  let state = 2166136261;
  const salt = `${pkg.id}|${pkg.caseId}|${pkg.scanId}|${pkg.createdAt}`;
  for (let i = 0; i < salt.length; i++) {
    state ^= salt.charCodeAt(i);
    state = Math.imul(state, 16777619);
  }
  while (seed.length < 64) {
    state = Math.imul(state ^ (state >>> 13), 2654435761) >>> 0;
    seed += state.toString(16).padStart(8, '0');
  }
  pkg.hash = seed.slice(0, 64);
  return true;
}

function renderEvidenceHashBlock(hash, { showCopy = false } = {}) {
  const hex = parseEvidenceHashHex(hash) || String(hash || '');
  const safeHex = escapeHtml(hex);
  const copyBtn = showCopy
    ? `<button type="button" class="btn-xs evidence-hash-copy" data-hash="${safeHex}" onclick="copyEvidenceHash(this)" title="Копировать контрольную сумму">Копировать</button>`
    : '';
  return `
    <div class="evidence-hash">
      <div class="evidence-hash-head">
        <span class="evidence-hash-label">Контрольная сумма (SHA-256)</span>
        ${copyBtn}
      </div>
      <p class="evidence-hash-hint muted" title="${escapeHtml(EVIDENCE_HASH_HINT)}">${escapeHtml(EVIDENCE_HASH_HINT)}</p>
      <code class="evidence-hash-value" title="${safeHex}">${safeHex}</code>
    </div>`;
}

function copyEvidenceHash(btn) {
  const hash = btn?.dataset?.hash || '';
  if (!hash) return;
  const done = () => showToast('Контрольная сумма скопирована');
  const fail = () => showToast('Не удалось скопировать контрольную сумму');
  if (navigator.clipboard?.writeText) {
    navigator.clipboard.writeText(hash).then(done).catch(fail);
    return;
  }
  const ta = document.createElement('textarea');
  ta.value = hash;
  ta.setAttribute('readonly', '');
  ta.style.position = 'fixed';
  ta.style.left = '-9999px';
  document.body.appendChild(ta);
  ta.select();
  try {
    if (document.execCommand('copy')) done();
    else fail();
  } catch {
    fail();
  } finally {
    ta.remove();
  }
}

const SEED_EVIDENCE_PACKAGES = [
  {
    id: 'ДОК-452101',
    caseId: 'ЕПСОК-2028-004521',
    scanId: 'OSINT-88510',
    findings: [
      { type: 'email', value: 'suspect.fraud@mail.ru', confidence: 100 },
      { type: 'phone', value: '+79001234567', confidence: 85 }
    ],
    hash: 'a3f8c91e2b4d7091e8c6f5a4b3d2e1c0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4',
    createdAt: '12.06.2028 10:22',
    createdBy: 'Иванов С.П.',
    status: 'sealed'
  },
  {
    id: 'ДОК-452102',
    caseId: 'ЕПСОК-2028-004521',
    scanId: 'OSINT-88510',
    findings: [
      { type: 'username', value: 'suspect_fraud_2028', confidence: 90 },
      { type: 'social_profile', value: 'Telegram: @suspect_fraud_2028', confidence: 88 },
      { type: 'social_profile', value: 'VK: vk.com/id123456789', confidence: 80 }
    ],
    hash: '7e2d9c41f8a1b6c3d5e7f9012345678abcdef0123456789abcdef0123456789a',
    createdAt: '12.06.2028 11:05',
    createdBy: 'Иванов С.П.',
    status: 'sealed'
  },
  {
    id: 'ДОК-289101',
    caseId: 'ЕПСОК-2028-002891',
    scanId: 'OSINT-88511',
    findings: [
      { type: 'phone', value: '+79009878901', confidence: 100 },
      { type: 'username', value: 'kazan_sim_8901', confidence: 84 }
    ],
    hash: 'b5c1e8f03a9271d4e6f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e',
    createdAt: '11.06.2028 17:18',
    createdBy: 'Иванов С.П.',
    status: 'sealed'
  },
  {
    id: 'ДОК-289102',
    caseId: 'ЕПСОК-2028-002891',
    scanId: 'OSINT-88511',
    findings: [
      { type: 'social_profile', value: 'Telegram: @kazan_sim', confidence: 76 }
    ],
    hash: 'd4a7b2c19e5583f6a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0',
    createdAt: '11.06.2028 17:45',
    createdBy: 'Иванов С.П.',
    status: 'sealed'
  }
];

function resolveEvidencePackageCaseId(pkg) {
  if (pkg.caseId && getCaseById(pkg.caseId)) return pkg.caseId;
  const scan = osintScans.find(s => s.id === pkg.scanId);
  return getOsintScanCaseId(scan);
}

function normalizeEvidencePackages() {
  let changed = false;
  evidencePackages.forEach(p => {
    const resolved = resolveEvidencePackageCaseId(p);
    if (p.caseId !== resolved) {
      p.caseId = resolved;
      changed = true;
    }
    if (repairEvidencePackageHash(p)) changed = true;
  });
  if (changed) saveEvidencePackages();
}

function groupEvidencePackagesByCase(packages) {
  const groups = new Map();
  packages.forEach(p => {
    const caseId = p.caseId;
    if (!groups.has(caseId)) groups.set(caseId, []);
    groups.get(caseId).push(p);
  });
  return [...groups.entries()]
    .map(([caseId, pkgs]) => ({ caseId, packages: pkgs }))
    .sort((a, b) => {
      if (a.caseId === activeCaseId) return -1;
      if (b.caseId === activeCaseId) return 1;
      const aLatest = a.packages[0]?.createdAt || '';
      const bLatest = b.packages[0]?.createdAt || '';
      return bLatest.localeCompare(aLatest, 'ru');
    });
}

async function loadEvidencePackages() {
  let loaded = null;
  if (typeof EpsokSecurity !== 'undefined') {
    loaded = await EpsokSecurity.secureGetItem(sessionStorage, EVIDENCE_STORAGE_KEY);
  }
  if (!loaded) {
    try {
      const raw = sessionStorage.getItem(EVIDENCE_STORAGE_KEY);
      if (raw && !raw.startsWith('epsok:enc:')) loaded = JSON.parse(raw);
    } catch { /* ignore */ }
  }
  if (loaded) {
    evidencePackages = loaded;
    normalizeEvidencePackages();
    return;
  }
  evidencePackages = JSON.parse(JSON.stringify(SEED_EVIDENCE_PACKAGES));
  new Set(SEED_EVIDENCE_PACKAGES.map(p => p.caseId)).forEach(id => expandedEvidenceCaseGroups.add(id));
  await saveEvidencePackages();
}

async function saveEvidencePackages() {
  try {
    if (typeof EpsokSecurity !== 'undefined') {
      await EpsokSecurity.secureSetItem(sessionStorage, EVIDENCE_STORAGE_KEY, evidencePackages);
    } else {
      sessionStorage.setItem(EVIDENCE_STORAGE_KEY, JSON.stringify(evidencePackages));
    }
  } catch { /* ignore */ }
}

function toggleEvidenceCaseGroup(caseId) {
  if (expandedEvidenceCaseGroups.has(caseId)) expandedEvidenceCaseGroups.delete(caseId);
  else expandedEvidenceCaseGroups.add(caseId);
  renderEvidencePackages();
}

function isEvidenceCaseGroupExpanded(caseId) {
  return expandedEvidenceCaseGroups.has(caseId);
}

function buildEvidencePackagePdfHtml(pkg) {
  const caseInfo = getCaseById(pkg.caseId);
  const persona = getActivePersona();
  const exportedAt = new Date().toLocaleString('ru-RU');
  const findingsRows = pkg.findings.map((f, i) => `
    <tr>
      <td class="col-num">${i + 1}</td>
      <td><span class="type-tag">${escapeHtml(osintTypeLabels[f.type] || f.type)}</span></td>
      <td class="col-value">${escapeHtml(f.value)}</td>
      <td class="col-conf">${f.confidence != null ? f.confidence + '%' : '—'}</td>
    </tr>`).join('');

  return `<article class="evidence-pdf">
    <header class="evidence-pdf-brand">
      <div class="evidence-pdf-brand-title">ЕПСОК</div>
      <div class="evidence-pdf-brand-sub">Единая платформа следственно-оперативной координации</div>
    </header>
    <div class="evidence-pdf-head">
      <h1>Пакет доказательств</h1>
      <span class="evidence-pdf-badge">запечатан</span>
    </div>
    <dl class="evidence-pdf-meta">
      <div><dt>Идентификатор</dt><dd>${escapeHtml(pkg.id)}</dd></div>
      <div><dt>Дело</dt><dd>${escapeHtml(pkg.caseId)}${caseInfo?.crimeType ? ` · ${escapeHtml(caseInfo.crimeType)}` : ''}</dd></div>
      <div><dt>Проверка OSINT</dt><dd>${escapeHtml(formatScanId(pkg.scanId || '—'))}</dd></div>
      <div><dt>Сформирован</dt><dd>${escapeHtml(pkg.createdAt)} · ${escapeHtml(pkg.createdBy || persona.name)}</dd></div>
      <div class="evidence-pdf-meta-hash"><dt>Контрольная сумма (SHA-256)</dt><dd><span class="evidence-hash-hint">${escapeHtml(EVIDENCE_HASH_HINT)}</span><code class="evidence-hash-value">${escapeHtml(parseEvidenceHashHex(pkg.hash) || pkg.hash)}</code></dd></div>
    </dl>
    <h2 class="evidence-pdf-section">Объекты (${pkg.findings.length})</h2>
    <table class="evidence-pdf-table">
      <thead>
        <tr>
          <th>№</th>
          <th>Тип</th>
          <th>Значение</th>
          <th>Достоверность</th>
        </tr>
      </thead>
      <tbody>${findingsRows}</tbody>
    </table>
    <footer class="evidence-pdf-footer">
      <p>Выгрузка: ${escapeHtml(exportedAt)} · ${escapeHtml(persona.name)} · ${escapeHtml(persona.role || '')}</p>
      <p class="evidence-pdf-policy">Запись в журнал аудита · ПОЛ-004 · неизменяемый комплект OSINT</p>
    </footer>
  </article>`;
}

async function downloadEvidencePackagePdf(pkgId) {
  const pkg = evidencePackages.find(p => p.id === pkgId);
  if (!pkg) {
    showToast('Пакет доказательств не найден.');
    return;
  }
  if (!personaCanAccessCase(pkg.caseId)) {
    showToast('Нет доступа к пакету доказательств.');
    return;
  }
  if (typeof html2pdf === 'undefined') {
    showToast('Модуль PDF недоступен. Проверьте подключение к сети и обновите страницу.');
    return;
  }

  showToast(`${pkg.id}: формирование PDF…`);

  const host = document.createElement('div');
  host.className = 'evidence-pdf-host';
  host.innerHTML = buildEvidencePackagePdfHtml(pkg);
  document.body.appendChild(host);

  const filename = `${pkg.id.replace(/[^\w\d\-а-яА-ЯёЁ]/gi, '_')}.pdf`;

  try {
    await html2pdf().set({
      margin: [10, 10, 12, 10],
      filename,
      image: { type: 'jpeg', quality: 0.98 },
      html2canvas: { scale: 2, useCORS: true, letterRendering: true },
      jsPDF: { unit: 'mm', format: 'a4', orientation: 'portrait' }
    }).from(host.querySelector('.evidence-pdf') || host).save();
    showToast(`${pkg.id}: PDF сохранён · запись в журнал аудита (ПОЛ-004)`);
  } catch {
    showToast(`Ошибка выгрузки PDF: ${pkg.id}`);
  } finally {
    host.remove();
  }
}

function renderEvidencePackageCard(p) {
  const canDownload = personaCanAccessCase(p.caseId);
  return `
    <article class="evidence-package-card">
      <header class="evidence-package-head">
        <strong>${escapeHtml(p.id)}</strong>
        <span class="status fulfilled">${p.status === 'sealed' ? 'запечатан' : p.status}</span>
      </header>
      <p class="muted">проверка ${escapeHtml(formatScanId(p.scanId || '—'))} · ${escapeHtml(p.createdAt)}</p>
      <p class="muted">${p.findings.length} объектов</p>
      ${renderEvidenceHashBlock(p.hash, { showCopy: true })}
      <ul class="evidence-package-items">${p.findings.slice(0, 4).map(f => `<li><span class="type-tag">${osintTypeLabels[f.type] || f.type}</span> ${escapeHtml(f.value)}</li>`).join('')}${p.findings.length > 4 ? `<li class="muted">… ещё ${p.findings.length - 4}</li>` : ''}</ul>
      <div class="evidence-package-actions">
        <button type="button" class="btn-sm" onclick="openCase('${p.caseId}')">Карточка дела</button>
        ${canDownload ? `<button type="button" class="btn-sm" onclick="downloadEvidencePackagePdf('${p.id}')">Скачать PDF</button>` : ''}
      </div>
    </article>`;
}

function renderEvidenceCaseGroupHeader(caseId, count, caseInfo, expanded) {
  const managers = getCaseManagersDisplay(caseId).join(', ') || caseInfo?.lead || '—';
  const readonlyHint = isCaseReadOnly()
    ? '<span class="link-badge">только просмотр</span>'
    : '';
  return `
    <button type="button" class="evidence-case-group-head" onclick="toggleEvidenceCaseGroup('${caseId}')" aria-expanded="${expanded ? 'true' : 'false'}">
      <span class="evidence-case-group-chevron" aria-hidden="true">${expanded ? '▴' : '▾'}</span>
      <span class="evidence-case-group-meta">
        <span class="evidence-case-group-title">${escapeHtml(caseId)}</span>
        ${caseInfo ? `<span class="muted evidence-case-group-sub">${escapeHtml(caseInfo.article)} · ${escapeHtml(caseInfo.crimeType)}</span>` : ''}
        <span class="link-badge evidence-case-group-count">${count} ${count === 1 ? 'пакет' : count < 5 ? 'пакета' : 'пакетов'}</span>
        ${readonlyHint}
      </span>
      <span class="evidence-case-group-side muted">${escapeHtml(managers)}</span>
    </button>`;
}

function renderEvidencePackages() {
  const el = document.getElementById('evidence-packages-list');
  if (!el) return;
  normalizeEvidencePackages();
  const scoped = evidencePackages.filter(p => personaCanAccessCase(p.caseId));
  if (!scoped.length) {
    el.innerHTML = '<p class="muted evidence-empty">Пакетов пока нет. Выберите находки в таблице выше и нажмите «Сформировать пакет доказательств».</p>';
    return;
  }
  const grouped = groupEvidencePackagesByCase(scoped);
  el.innerHTML = grouped.map(({ caseId, packages }) => {
    const caseInfo = getCaseById(caseId);
    const expanded = isEvidenceCaseGroupExpanded(caseId);
    return `
      <section class="evidence-case-group" data-case-id="${escapeHtml(caseId)}">
        ${renderEvidenceCaseGroupHeader(caseId, packages.length, caseInfo, expanded)}
        <div class="evidence-case-group-body${expanded ? '' : ' collapsed'}">
          <div class="evidence-packages-list">${packages.map(renderEvidencePackageCard).join('')}</div>
        </div>
      </section>`;
  }).join('');
}

function scrollToEvidencePackages() {
  showView('osint');
  if (activeCaseId) expandedEvidenceCaseGroups.add(activeCaseId);
  setTimeout(() => {
    renderEvidencePackages();
    document.getElementById('evidence-packages-panel')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, 150);
}

selectedOsintScanId = 'OSINT-88510';

// --- Horizon Intelligence — 7 modules (demo) ---

let activeHorizonCaseId = 'ЕПСОК-2028-004521';
let horizonState = {
  firStatus: 'pending',
  firConfidence: 76,
  seRevealRequested: false,
  ghostRequestSent: false,
  proRequestSent: false,
  tcrRefreshed: false,
  mormScore: 87,
  twinSimulated: false,
  lastSimulationModule: null,
  lastSimulationAt: null,
  alerts: []
};

const horizonProfilesByCase = {
  'ЕПСОК-2028-004521': {
    cluster: 'МВ-2847',
    peerCase: 'ЕПСОК-2028-001234',
    peerPlace: 'Москва',
    firChecksum: 'a3f2…9c1d',
    twinScenarios: [
      { id: 't1', name: 'CDR по SIM +7***8901', yield: '+12 узлов', sla: '4 часа', risk: '−3 дня к сроку', score: 72 },
      { id: 't2', name: 'РФМ по счёту ***4521', yield: '+8 узлов', sla: '1,5 дня', risk: '−1 день', score: 91, best: true },
      { id: 't3', name: 'ФНС по ООО «Номинал»', yield: '+5 узлов + скрытая связь', sla: '1 день', risk: '−1 день', score: 85 }
    ],
    ghostPath: [
      { type: 'person', label: 'Подозреваемый А' },
      { type: 'org', label: 'ООО «Номинал»' },
      { type: 'person', label: 'Бухгалтер B' },
      { type: 'account', label: 'Счёт ***4521' }
    ],
    cooccurrence: [
      { at: '03.01.2028 14:22', a: 'SIM подозреваемого', b: 'Базовая станция · Краснодар', source: 'CDR (запрос исполнен)' },
      { at: '05.01.2028 11:05', a: 'Счёт ***4521', b: 'Перевод 847 000 ₽', source: 'РФМ' },
      { at: '05.01.2028 11:07', a: 'SIM Москва', b: 'Тот же цифровой отпечаток', source: 'Индекс совпадений' },
      { at: '12.06.2028 09:14', a: 'Почта из открытых источников', b: 'Профиль ВК', source: 'Открытые источники' }
    ],
    proRows: [
      { rank: 1, name: 'Движение средств', agency: 'РФМ', add: '+8', sla: '1,5 дня', score: 91 },
      { rank: 2, name: 'ЕГРЮЛ', agency: 'ФНС', add: '+5', sla: '1 день', score: 85 },
      { rank: 3, name: 'CDR', agency: 'МВД', add: '+12', sla: '4 ч', score: 72 }
    ]
  },
  'ЕПСОК-2028-001234': {
    cluster: 'МВ-2847',
    peerCase: 'ЕПСОК-2028-004521',
    peerPlace: 'Краснодар',
    firChecksum: 'b8e1…4a7c',
    twinScenarios: [
      { id: 'm1', name: 'РФМ: оборот счёта ***4521', yield: '+6 узлов', sla: '1 день', risk: '−2 дня', score: 88, best: true },
      { id: 'm2', name: 'ФНС: бенефициары ООО', yield: '+4 узла', sla: '1 день', risk: '−1 день', score: 79 },
      { id: 'm3', name: 'СМЭВ: связь с SIM Казань', yield: '+3 узла', sla: '2 дня', risk: '−1 день', score: 74 }
    ],
    ghostPath: [
      { type: 'account', label: 'Счёт ***4521' },
      { type: 'org', label: 'ООО «Номинал»' },
      { type: 'person', label: 'Номинальный директор' },
      { type: 'case', label: 'ЕПСОК-004521' }
    ],
    cooccurrence: [
      { at: '15.01.2028 10:00', a: 'Счёт ***4521', b: '23 входящих перевода', source: 'РФМ' },
      { at: '05.02.2028 09:30', a: 'SIM +7***8901', b: 'Совпадение с Краснодаром', source: 'Индекс совпадений' }
    ],
    proRows: [
      { rank: 1, name: 'Бенефициарный контроль', agency: 'ФНС', add: '+4', sla: '1 день', score: 88 },
      { rank: 2, name: 'CDR Москва', agency: 'МВД', add: '+7', sla: '4 ч', score: 81 },
      { rank: 3, name: 'Запрос в СК (смежное)', agency: 'СК', add: '+2', sla: '1 день', score: 65 }
    ]
  },
  'ЕПСОК-2028-002891': {
    cluster: 'МВ-2847',
    peerCase: 'ЕПСОК-2028-004521',
    peerPlace: 'Краснодар',
    firChecksum: 'c4d9…1f2e',
    twinScenarios: [
      { id: 'k1', name: 'CDR SIM +7***8901', yield: '+9 узлов', sla: '4 ч', risk: '−2 дня', score: 86, best: true },
      { id: 'k2', name: 'Telegram @kazan_sim', yield: '+3 узла', sla: '6 ч', risk: '−0.5 дня', score: 71 },
      { id: 'k3', name: 'ГИАЦ: владелец SIM', yield: '+5 узлов', sla: '2 дня', risk: '−1 день', score: 68 }
    ],
    ghostPath: [
      { type: 'phone', label: 'SIM +7***8901' },
      { type: 'username', label: '@kazan_sim' },
      { type: 'person', label: 'Номинал SIM' },
      { type: 'case', label: 'ЕПСОК-004521' }
    ],
    cooccurrence: [
      { at: '14.03.2028 08:15', a: 'SIM +7***8901', b: 'Кластер МВ-2847', source: 'Индекс совпадений' },
      { at: '14.03.2028 08:20', a: 'Telegram', b: 'Профиль @kazan_sim', source: 'Открытые источники' }
    ],
    proRows: [
      { rank: 1, name: 'CDR / базовые станции', agency: 'МВД', add: '+9', sla: '4 ч', score: 86 },
      { rank: 2, name: 'ГИАЦ владелец SIM', agency: 'МВД', add: '+5', sla: '2 дня', score: 68 },
      { rank: 3, name: 'Раскрытие смежного дела', agency: 'ЕПСОК', add: '+4', sla: '1 день', score: 62 }
    ]
  }
};

function getHorizonProfile(caseId) {
  return horizonProfilesByCase[caseId] || horizonProfilesByCase['ЕПСОК-2028-004521'];
}

function resetHorizonStateForCase() {
  horizonState = {
    firStatus: 'pending',
    firConfidence: getHorizonProfile(activeHorizonCaseId).firChecksum ? 76 : 60,
    seRevealRequested: false,
    ghostRequestSent: false,
    proRequestSent: false,
    tcrRefreshed: false,
    mormScore: 87,
    twinSimulated: false,
    lastSimulationModule: null,
    lastSimulationAt: null,
    alerts: []
  };
}

function selectHorizonCase(caseId) {
  if (!personaCanAccessCase(caseId)) {
    showToast('ПОЛ-007: нет доступа к делу.');
    return;
  }
  activeHorizonCaseId = caseId;
  activeCaseId = caseId;
  resetHorizonStateForCase();
  renderHorizon();
  updateHeaderContext();
}

function pushHorizonAlert(text, level = 'info') {
  horizonState.alerts.unshift({ text, level, at: new Date().toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' }) });
  if (horizonState.alerts.length > 5) horizonState.alerts.pop();
}

let activeHorizonModule = 'SE';

const horizonModules = [
  { id: 'SE', name: 'Движок совпадений', icon: '◈', color: '#a855f7', runLabel: 'Сканировать индекс' },
  { id: 'GLD', name: 'Детектор скрытых связей', icon: '👻', color: '#8b5cf6', runLabel: 'Построить путь' },
  { id: 'TCR', name: 'Временные пересечения', icon: '⏱', color: '#06b6d4', runLabel: 'Обновить хронологию' },
  { id: 'MORM', name: 'Совпадение с кластером', icon: '◎', color: '#ec4899', runLabel: 'Пересчитать сходство' },
  { id: 'IDT', name: 'Цифровой двойник', icon: '⧉', color: '#3b82f6', runLabel: 'Симулировать запросы' },
  { id: 'PRO', name: 'Прогноз запросов', icon: '⚡', color: '#10b981', runLabel: 'Ранжировать запросы' },
  { id: 'FIR', name: 'Федеративная идентификация', icon: '⊛', color: '#f59e0b', runLabel: 'Проверить гипотезу' }
];

function renderHorizonCasePicker() {
  const sel = document.getElementById('horizon-case-picker');
  if (!sel) return;
  const cases = getPersonaScopedCases().filter(c => c.cluster || c.related?.length);
  const list = cases.length ? cases : getPersonaScopedCases().slice(0, 5);
  if (!list.some(c => c.id === activeHorizonCaseId)) activeHorizonCaseId = list[0]?.id || activeCaseId;
  sel.innerHTML = list.map(c => `<option value="${c.id}" ${c.id === activeHorizonCaseId ? 'selected' : ''}>${c.id} · ${escapeHtml(c.region)}</option>`).join('');
  const btn = document.getElementById('horizon-run-btn');
  const mod = horizonModules.find(m => m.id === activeHorizonModule);
  if (btn && mod) btn.textContent = `▶ ${mod.runLabel}`;
}

function renderHorizonAlerts() {
  const el = document.getElementById('horizon-alerts');
  if (!el) return;
  if (!horizonState.alerts.length) {
    el.innerHTML = '';
    el.classList.add('hidden');
    return;
  }
  el.classList.remove('hidden');
  el.innerHTML = horizonState.alerts.map(a => `
    <div class="horizon-alert-item ${a.level}"><span class="horizon-alert-time">${a.at}</span>${escapeHtml(a.text)}</div>
  `).join('');
}

function renderHorizonModulesGrid() {
  const grid = document.getElementById('horizon-modules-grid');
  if (!grid) return;
  const profile = getHorizonProfile(activeHorizonCaseId);
  const metrics = {
    SE: horizonState.seRevealRequested ? 'запрос отправлен' : `1 сигнал · ${profile.peerPlace}`,
    GLD: horizonState.ghostRequestSent ? 'путь подтверждён' : `глубина ${profile.ghostPath.length}`,
    TCR: horizonState.tcrRefreshed ? `${profile.cooccurrence.length + 2} событий` : `${profile.cooccurrence.length} событий`,
    MORM: `${horizonState.mormScore}%`,
    IDT: horizonState.twinSimulated ? 'пересчитано' : `${profile.twinScenarios.length} сценария`,
    PRO: horizonState.proRequestSent ? 'запрос создан' : `#1 ${profile.proRows[0].agency}`,
    FIR: horizonState.firStatus === 'pending' ? 'ожидает' : horizonState.firStatus === 'confirmed' ? 'подтверждено' : horizonState.firStatus === 'rejected' ? 'отклонено' : 'ГИАЦ'
  };
  grid.innerHTML = horizonModules.map(m => `
    <button type="button" class="hz-module-card ${activeHorizonModule === m.id ? 'active' : ''}"
      style="--hz-color: ${m.color}"
      onclick="selectHorizonModule('${m.id}')">
      <span class="hz-mod-id">${m.id}</span>
      <span class="hz-mod-icon">${m.icon}</span>
      <span class="hz-mod-name">${m.name}</span>
      <span class="hz-mod-metric">${metrics[m.id]}</span>
    </button>
  `).join('');
}

function selectHorizonModule(id) {
  activeHorizonModule = id;
  renderHorizon();
}

function renderHorizonModuleDetail(id) {
  const el = document.getElementById('horizon-module-detail');
  if (!el) return;
  const mod = horizonModules.find(m => m.id === id);
  const profile = getHorizonProfile(activeHorizonCaseId);
  const c = getCaseById(activeHorizonCaseId);
  let body = '';
  let actions = '';

  if (id === 'SE') {
    body = `<div class="horizon-alert-card critical serendipity">
      <div class="ha-head"><span class="ha-type">◈ Совпадение</span><span class="ha-time">${horizonState.seRevealRequested ? 'обновлено' : '14.06.2028 03:14'}</span></div>
      <h3>Общий цифровой отпечаток с делом ${escapeHtml(profile.peerPlace)}</h3>
      <p>SIM +7 (***) ***-89-01 · индекс совпадений · ${horizonState.seRevealRequested ? '96' : '94'}% · дело ${escapeHtml(activeHorizonCaseId)}.</p>
      <p class="ha-peer">↔ ${escapeHtml(profile.peerCase)} · ${escapeHtml(profile.peerPlace)}</p>
      ${horizonState.seRevealRequested ? '<p class="link-badge">Запрос раскрытия в очереди · SLA 4 ч</p>' : ''}
    </div>`;
    actions = `<button type="button" class="btn-sm" onclick="requestPeerReveal('${profile.peerCase}')">${horizonState.seRevealRequested ? '↻ Статус запроса' : 'Запросить раскрытие'}</button>
      <button type="button" class="btn-sm" onclick="openCase('${profile.peerCase}')">Открыть смежное дело</button>`;
  } else if (id === 'GLD') {
    body = `<div class="ghost-path">${profile.ghostPath.map((n, i) => `
      <div class="ghost-node ${n.type}"><span class="ghost-dot"></span><span>${escapeHtml(n.label)}</span></div>
      ${i < profile.ghostPath.length - 1 ? '<div class="ghost-arrow">→</div>' : ''}
    `).join('')}</div>${horizonState.ghostRequestSent ? '<p class="link-badge">Межвед. запрос ФНС №88504 создан</p>' : '<p class="muted">Скрытый путь через номинала · уверенность 88%</p>'}`;
    actions = `<button type="button" class="btn-sm" onclick="createRequestFromGhost()">${horizonState.ghostRequestSent ? '↻ Статус запроса' : '+ Межвед. запрос (ФНС)'}</button>`;
  } else if (id === 'TCR') {
    const events = horizonState.tcrRefreshed
      ? [...profile.cooccurrence, { at: '14.06.2028 11:02', a: 'Новое пересечение', b: 'БС · ' + (c?.region || ''), source: 'Автообновление' }, { at: '14.06.2028 11:03', a: 'SIM', b: 'Платёжный шлюз', source: 'РФМ (очередь)' }]
      : profile.cooccurrence;
    body = `<div class="cooccurrence-timeline">${events.map(e => `
      <div class="co-item"><span class="co-time">${e.at}</span><div class="co-body"><strong>${escapeHtml(e.a)}</strong> ↔ ${escapeHtml(e.b)}<span class="co-src">${escapeHtml(e.source)}</span></div></div>
    `).join('')}</div>`;
    actions = '<button type="button" class="btn-sm" onclick="runHorizonSimulation(\'TCR\')">↻ Обновить ленту</button>';
  } else if (id === 'MORM') {
    body = `<div class="mo-resonance">
      <div class="mo-score-ring"><span class="mo-score">${horizonState.mormScore}</span><span class="mo-score-label">сходство</span></div>
      <ul class="mo-factors"><li>Кластер ${escapeHtml(profile.cluster)}</li><li>${escapeHtml(c?.crimeType || '—')} · ${escapeHtml(c?.region || '—')}</li><li>Прорыв: ${escapeHtml(profile.proRows[0].agency)} + ${escapeHtml(profile.proRows[1].agency)}</li></ul>
    </div>`;
    actions = '<button type="button" class="btn-sm" onclick="runHorizonSimulation(\'MORM\')">↻ Пересчитать</button>';
  } else if (id === 'IDT') {
    const scenarios = profile.twinScenarios.map(s => {
      const score = horizonState.twinSimulated && s.best ? Math.min(99, s.score + 2) : s.score;
      return { ...s, score, best: s.best };
    });
    body = `<div class="twin-grid">${scenarios.map(s => `
      <div class="twin-card ${s.best ? 'best' : ''}">
        ${s.best ? '<span class="twin-badge">Оптимум</span>' : ''}
        <div class="twin-name">${escapeHtml(s.name)}</div>
        <div class="twin-stats"><span>${s.yield}</span><span>SLA ${s.sla}</span><span>${s.risk}</span></div>
        <div class="twin-score-bar"><div style="width:${s.score}%"></div></div>
        <div class="twin-score-num">${s.score}/100</div>
      </div>
    `).join('')}</div>${horizonState.twinSimulated ? `<p class="muted">Симуляция завершена · ${new Date().toLocaleTimeString('ru-RU')}</p>` : ''}`;
    actions = `<button type="button" class="btn-primary btn-sm-inline" onclick="runHorizonSimulation('IDT')">${horizonState.twinSimulated ? '↻ Пересимулировать' : '▶ Симулировать сценарии'}</button>`;
  } else if (id === 'PRO') {
    body = `<div class="table-scroll"><table class="data-table"><thead><tr><th>#</th><th>Запрос</th><th>Ведомство</th><th>Добавит</th><th>SLA</th><th>Оценка</th></tr></thead><tbody>
      ${profile.proRows.map(r => `<tr class="${r.rank === 1 ? 'row-highlight' : ''}"><td>${r.rank}</td><td>${escapeHtml(r.name)}</td><td>${escapeHtml(r.agency)}</td><td>${r.add}</td><td>${r.sla}</td><td><strong>${r.score}</strong></td></tr>`).join('')}
    </tbody></table></div>${horizonState.proRequestSent ? '<p class="link-badge">Запрос №88504 создан по рекомендации #1</p>' : ''}`;
    actions = `<button type="button" class="btn-sm" onclick="createRequestFromGhost()">${horizonState.proRequestSent ? '↻ Статус' : 'Создать запрос №1'}</button>`;
  } else if (id === 'FIR') {
    const firLabels = { pending: 'ожидает', giac: 'запрос в ГИАЦ', confirmed: 'подтверждено', rejected: 'отклонено' };
    const firClass = horizonState.firStatus === 'confirmed' ? 'fulfilled' : horizonState.firStatus === 'rejected' ? 'draft' : 'progress';
    body = `<div class="fir-card">
      <p><strong>Контрольная сумма ФИО:</strong> <code>${profile.firChecksum}</code> · уверенность ${horizonState.firConfidence}%</p>
      <p class="muted">Дело ${escapeHtml(activeHorizonCaseId)} · смежное: ${escapeHtml(profile.peerCase)}</p>
      <p>Статус: <span class="status ${firClass}" id="fir-status-badge">${firLabels[horizonState.firStatus] || horizonState.firStatus}</span></p>
      ${horizonState.firStatus === 'giac' ? '<p class="link-badge">Запрос ГИАЦ №4421 · SLA 2 раб. дня</p>' : ''}
    </div>`;
    actions = `<button type="button" class="btn-xs approve" onclick="confirmFir()" ${horizonState.firStatus === 'confirmed' ? 'disabled' : ''}>Подтвердить</button>
      <button type="button" class="btn-xs reject" onclick="rejectFir()" ${horizonState.firStatus === 'rejected' ? 'disabled' : ''}>Отклонить</button>
      <button type="button" class="btn-sm" onclick="requestGiacForFir()">${horizonState.firStatus === 'giac' ? '↻ Статус ГИАЦ' : 'Запрос ГИАЦ'}</button>`;
  }

  el.innerHTML = `
    <div class="panel hz-detail-panel">
      <div class="panel-header"><h2><span class="hz-detail-id">${mod.id}</span> ${mod.name}</h2><span class="muted">${escapeHtml(activeHorizonCaseId)}</span></div>
      <div class="hz-detail-body">${body}</div>
      ${actions ? `<div class="ha-actions">${actions}</div>` : ''}
    </div>`;
}

function renderHorizon() {
  renderHorizonCasePicker();
  renderHorizonModulesGrid();
  renderHorizonAlerts();
  renderHorizonModuleDetail(activeHorizonModule);
}

function runHorizonSimulation(moduleId) {
  const mod = moduleId || activeHorizonModule;
  const profile = getHorizonProfile(activeHorizonCaseId);
  horizonState.lastSimulationModule = mod;
  horizonState.lastSimulationAt = new Date().toLocaleString('ru-RU');

  switch (mod) {
    case 'SE':
      horizonState.seRevealRequested = true;
      pushHorizonAlert(`SE: запрос раскрытия ${profile.peerCase} поставлен в очередь`, 'info');
      showToast(`Движок совпадений: запрос раскрытия → ${profile.peerCase}`);
      break;
    case 'GLD':
      horizonState.ghostRequestSent = true;
      pushHorizonAlert('GLD: скрытый путь подтверждён · черновик запроса ФНС', 'info');
      showToast('Детектор: путь через номинала подтверждён · запрос ФНС');
      break;
    case 'TCR':
      horizonState.tcrRefreshed = true;
      pushHorizonAlert('TCR: добавлено 2 события в хронологию пересечений', 'info');
      showToast('Временные пересечения: лента обновлена (+2 события)');
      break;
    case 'MORM':
      horizonState.mormScore = Math.min(99, horizonState.mormScore + 4);
      pushHorizonAlert(`MORM: сходство с ${profile.cluster} → ${horizonState.mormScore}%`, 'info');
      showToast(`Совпадение с кластером: ${horizonState.mormScore}%`);
      break;
    case 'IDT':
      horizonState.twinSimulated = true;
      pushHorizonAlert(`IDT: оптимум — ${profile.twinScenarios.find(s => s.best)?.name || 'сценарий 1'}`, 'success');
      showToast(`Цифровой двойник: оптимум — ${profile.twinScenarios.find(s => s.best)?.agency || 'РФМ'} (${profile.twinScenarios.find(s => s.best)?.score || 91})`);
      break;
    case 'PRO':
      horizonState.proRequestSent = true;
      pushHorizonAlert(`PRO: создан запрос ${profile.proRows[0].agency} · ${profile.proRows[0].name}`, 'success');
      showToast(`Прогноз: запрос ${profile.proRows[0].agency} создан`);
      break;
    case 'FIR':
      if (horizonState.firStatus === 'pending') {
        horizonState.firStatus = 'giac';
        horizonState.firConfidence = Math.min(95, horizonState.firConfidence + 8);
        pushHorizonAlert('FIR: отправлен запрос в ГИАЦ для подтверждения', 'info');
        showToast('Федеративная идентификация: запрос в ГИАЦ отправлен');
      } else {
        horizonState.firConfidence = Math.min(98, horizonState.firConfidence + 3);
        showToast('FIR: статус ГИАЦ обновлён');
      }
      break;
    default:
      showToast('Модуль не поддерживает симуляцию');
  }
  renderHorizon();
}

function confirmFir() {
  if (horizonState.firStatus === 'rejected') return;
  horizonState.firStatus = 'confirmed';
  horizonState.firConfidence = Math.min(99, horizonState.firConfidence + 12);
  pushHorizonAlert('FIR: гипотеза «тот же субъект» подтверждена', 'success');
  renderHorizon();
  showToast('Идентификация подтверждена · запись в журнал');
}

function rejectFir() {
  if (horizonState.firStatus === 'confirmed') return;
  horizonState.firStatus = 'rejected';
  horizonState.firConfidence = Math.max(20, horizonState.firConfidence - 30);
  pushHorizonAlert('FIR: гипотеза отклонена', 'warn');
  renderHorizon();
  showToast('Идентификация отклонена · запись в журнал');
}

function requestGiacForFir() {
  if (horizonState.firStatus === 'confirmed' || horizonState.firStatus === 'rejected') {
    showToast(`Статус FIR: ${horizonState.firStatus === 'confirmed' ? 'подтверждено' : 'отклонено'}`);
    return;
  }
  horizonState.firStatus = 'giac';
  horizonState.firConfidence = Math.min(92, horizonState.firConfidence + 6);
  pushHorizonAlert('FIR: запрос в ГИАЦ №4421', 'info');
  renderHorizon();
  showToast('Запрос в ГИАЦ отправлен · SLA 2 раб. дня');
}

function requestPeerReveal(peerCase) {
  horizonState.seRevealRequested = true;
  pushHorizonAlert(`SE: раскрытие ${peerCase} → руководитель + прокуратура`, 'info');
  renderHorizon();
  showToast(`Запрос раскрытия ${peerCase} → руководитель + прокуратура`);
}

function createRequestFromGhost() {
  if (activeHorizonModule === 'PRO' || activeHorizonModule === 'GLD') {
    horizonState.proRequestSent = true;
    horizonState.ghostRequestSent = true;
  }
  const profile = getHorizonProfile(activeHorizonCaseId);
  pushHorizonAlert(`Создан запрос ${profile.proRows[0].agency} · ${profile.proRows[0].name}`, 'success');
  renderHorizon();
  showToast(`Запрос-88504: ${profile.proRows[0].agency} · ${activeHorizonCaseId}`);
}

function runTwinSimulation() { runHorizonSimulation('IDT'); }

// --- Tech Admin Console ---

const STAFF_USERS_ICON = '<svg class="icon-staff-users" viewBox="0 0 24 24" width="1em" height="1em" aria-hidden="true" xmlns="http://www.w3.org/2000/svg"><path d="M12.3 12.22C12.8336 11.7581 13.2616 11.1869 13.5549 10.545C13.8482 9.90316 14 9.20571 14 8.5C14 7.17392 13.4732 5.90215 12.5355 4.96447C11.5979 4.02678 10.3261 3.5 9 3.5C7.67392 3.5 6.40215 4.02678 5.46447 4.96447C4.52678 5.90215 4 7.17392 4 8.5C3.99999 9.20571 4.1518 9.90316 4.44513 10.545C4.73845 11.1869 5.16642 11.7581 5.7 12.22C4.30014 12.8539 3.11247 13.8775 2.27898 15.1685C1.4455 16.4596 1.00147 17.9633 1 19.5C1 19.7652 1.10536 20.0196 1.29289 20.2071C1.48043 20.3946 1.73478 20.5 2 20.5C2.26522 20.5 2.51957 20.3946 2.70711 20.2071C2.89464 20.0196 3 19.7652 3 19.5C3 17.9087 3.63214 16.3826 4.75736 15.2574C5.88258 14.1321 7.4087 13.5 9 13.5C10.5913 13.5 12.1174 14.1321 13.2426 15.2574C14.3679 16.3826 15 17.9087 15 19.5C15 19.7652 15.1054 20.0196 15.2929 20.2071C15.4804 20.3946 15.7348 20.5 16 20.5C16.2652 20.5 16.5196 20.3946 16.7071 20.2071C16.8946 20.0196 17 19.7652 17 19.5C16.9985 17.9633 16.5545 16.4596 15.721 15.1685C14.8875 13.8775 13.6999 12.8539 12.3 12.22ZM9 11.5C8.40666 11.5 7.82664 11.3241 7.33329 10.9944C6.83994 10.6648 6.45542 10.1962 6.22836 9.64805C6.0013 9.09987 5.94189 8.49667 6.05764 7.91473C6.1734 7.33279 6.45912 6.79824 6.87868 6.37868C7.29824 5.95912 7.83279 5.6734 8.41473 5.55764C8.99667 5.44189 9.59987 5.5013 10.1481 5.72836C10.6962 5.95542 11.1648 6.33994 11.4944 6.83329C11.8241 7.32664 12 7.90666 12 8.5C12 9.29565 11.6839 10.0587 11.1213 10.6213C10.5587 11.1839 9.79565 11.5 9 11.5ZM18.74 11.82C19.38 11.0993 19.798 10.2091 19.9438 9.25634C20.0896 8.30362 19.9569 7.32907 19.5618 6.45C19.1666 5.57093 18.5258 4.8248 17.7165 4.30142C16.9071 3.77805 15.9638 3.49974 15 3.5C14.7348 3.5 14.4804 3.60536 14.2929 3.79289C14.1054 3.98043 14 4.23478 14 4.5C14 4.76522 14.1054 5.01957 14.2929 5.20711C14.4804 5.39464 14.7348 5.5 15 5.5C15.7956 5.5 16.5587 5.81607 17.1213 6.37868C17.6839 6.94129 18 7.70435 18 8.5C17.9986 9.02524 17.8593 9.5409 17.5961 9.99542C17.3328 10.4499 16.9549 10.8274 16.5 11.09C16.3517 11.1755 16.2279 11.2977 16.1404 11.4447C16.0528 11.5918 16.0045 11.7589 16 11.93C15.9958 12.0998 16.0349 12.2678 16.1137 12.4183C16.1924 12.5687 16.3081 12.6967 16.45 12.79L16.84 13.05L16.97 13.12C18.1754 13.6917 19.1923 14.596 19.901 15.7263C20.6096 16.8566 20.9805 18.1659 20.97 19.5C20.97 19.7652 21.0754 20.0196 21.2629 20.2071C21.4504 20.3946 21.7048 20.5 21.97 20.5C22.2352 20.5 22.4896 20.3946 22.6771 20.2071C22.8646 20.0196 22.97 19.7652 22.97 19.5C22.9782 17.9654 22.5938 16.4543 21.8535 15.1101C21.1131 13.7659 20.0413 12.6333 18.74 11.82Z" fill="currentColor"/></svg>';

let activeAdminModule = 'SVC';
let auditFilterUser = '';
let auditFilterAction = '';
let auditFilterQuery = '';
let auditFilterPeriod = 'all';
let activeStaffStructure = 'МВД России';
let expandedStructurePersona = null;

const adminModules = [
  { id: 'SVC', name: 'Мониторинг', icon: '◫', color: '#10b981', summary: 'Сервисы платформы и показатели доступности', badge: '12/12', kinds: ['tech'] },
  { id: 'SES', name: 'Сессии', icon: '◎', color: '#3b82f6', summary: 'Тех. подключения · IP, АРМ, VPN', badge: null, kinds: ['tech'] },
  { id: 'STR', name: 'Структуры', icon: '▣', color: '#06b6d4', summary: 'Все ведомства · полные тех. данные', badge: null, kinds: ['tech'] },
  { id: 'INT', name: 'Интеграции', icon: '⇄', color: '#06b6d4', summary: 'СМЭВ и адаптеры ведомств', badge: '1', kinds: ['tech'] },
  { id: 'OSW', name: 'Сбор открытых источников', icon: '⌕', color: '#f59e0b', summary: 'Перечень модулей, кластер исполнителей', badge: '4', kinds: ['tech'] },
  { id: 'HZM', name: 'Горизонт', icon: '◈', color: '#a855f7', summary: 'Модули аналитики, индекс совпадений', badge: '7/7', kinds: ['tech'] },
  { id: 'CFG', name: 'Функции платформы', icon: '⚑', color: '#8b5cf6', summary: 'Включение функций по регионам', badge: '8', kinds: ['tech'] },
  { id: 'OPS', name: 'Операции', icon: '⏱', color: '#ef4444', summary: 'Очистка, ключи, обслуживание', badge: '1', kinds: ['tech'] },
  { id: 'LOG', name: 'Журнал аудита', icon: '☰', color: '#64748b', summary: 'WORM · неизменяемая запись', badge: null, kinds: ['tech', 'func'] },
  { id: 'USR', name: 'Учётные записи', icon: '👤', color: '#3b82f6', summary: 'Заявки на УЗ ведомства', badge: '3', kinds: ['func'] },
  { id: 'ROL', name: 'Роли и доступы', icon: '⚿', color: '#6366f1', summary: 'Матрица ролей · назначение прав', badge: '12', kinds: ['func'] },
  { id: 'PPL', name: 'Персонал', icon: STAFF_USERS_ICON, color: '#06b6d4', summary: 'Сотрудники ведомства · без тех. сессий', badge: null, kinds: ['func'] }
];

const adminServices = [
  { id: 'case-management', status: 'healthy', version: '1.4.2', ready: 3, desired: 3, p99: 42 },
  { id: 'link-intelligence', status: 'healthy', version: '1.4.0', ready: 2, desired: 2, p99: 118 },
  { id: 'interagency-hub', status: 'healthy', version: '1.3.8', ready: 4, desired: 4, p99: 89 },
  { id: 'osint-orchestrator', status: 'degraded', version: '0.9.1', ready: 3, desired: 4, p99: 210 },
  { id: 'horizon-orchestrator', status: 'healthy', version: '0.8.0', ready: 2, desired: 2, p99: 156 },
  { id: 'audit-worm', status: 'healthy', version: '1.0.0', ready: 2, desired: 2, p99: 12 }
];

const adminIntegrations = [
  { agency: 'SMEV', status: 'online', queue: 12, cert: '2028-09-14' },
  { agency: 'MVD / ГИАЦ', status: 'online', queue: 4, cert: '2028-11-02' },
  { agency: 'ФНС', status: 'online', queue: 0, cert: '2028-07-28' },
  { agency: 'РФМ', status: 'degraded', queue: 28, cert: '2028-06-20' },
  { agency: 'ФТС', status: 'cert_expiring', queue: 2, cert: '2028-06-18' }
];

const adminAuditLogTech = [
  { time: '14.06 15:40', user: 'Иванов С.П.', action: 'Просмотр дела', object: 'ЕПСОК-2028-004521 · метаданные', policy: 'ПОЛ-001' },
  { time: '14.06 15:12', user: 'Иванов С.П.', action: 'Запуск OSINT', object: 'ЕПСОК-2028-004521 · sfp_email, sfp_phone', policy: 'ПОЛ-006' },
  { time: '14.06 14:55', user: 'Морозова Е.А.', action: 'Экспорт графа', object: 'ЕПСОК-2028-005102 · PDF · 47 узлов', policy: 'ПОЛ-004' },
  { time: '14.06 14:22', user: 'Сидоров А.В.', action: 'Изменение конфигурации', object: 'osint.enabled · регионы 23, 77, 16', policy: 'ПОЛ-014' },
  { time: '14.06 13:48', user: 'Петрова А.К.', action: 'Межвед. запрос', object: 'Запрос-88422 · ФНС · ЕГРЮЛ', policy: 'ПОЛ-003' },
  { time: '14.06 13:05', user: 'Сидоров А.В.', action: 'Ротация сертификата', object: 'адаптер ФТС · СМЭВ', policy: 'ПОЛ-012' },
  { time: '14.06 12:30', user: 'Иванов С.П.', action: 'Создание дела', object: 'ЕПСОК-2028-004521 · возбуждение', policy: 'ПОЛ-001' },
  { time: '14.06 11:18', user: 'Сидоров А.В.', action: 'Запрос изменения перечня OSINT', object: 'sfp_webanalyze · двойной контроль', policy: 'ПОЛ-006' },
  { time: '14.06 10:02', user: 'Кузнецова Л.В.', action: 'Просмотр сроков', object: 'ЕПСОК-2028-004521 · надзор', policy: 'ПОЛ-002' },
  { time: '13.06 22:00', user: 'system', action: 'Плановая очистка', object: 'job-8841 · osint_purge · dry-run', policy: 'ПОЛ-010' },
  { time: '13.06 18:15', user: 'Иванов С.П.', action: 'Просмотр дела', object: 'ЕПСОК-2028-003891 · метаданные', policy: 'ПОЛ-001' },
  { time: '13.06 16:30', user: 'Сидоров А.В.', action: 'Пересборка индекса', object: 'horizon.bloom · 12 847 записей', policy: 'ПОЛ-014' },
  { time: '13.06 14:20', user: 'Сидоров М.В.', action: 'Просмотр графа', object: 'ЕПСОК-2028-002105 · 23 узла', policy: 'ПОЛ-001' },
  { time: '13.06 09:08', user: 'Сидоров А.В.', action: 'Экспорт в SIEM', object: 'admin.audit · 847 событий · 24 ч', policy: 'ПОЛ-004' },
  { time: '12.06 18:44', user: 'Сидоров А.В.', action: 'Окно обслуживания', object: 'osint-orchestrator · 22.06 01:00–03:00', policy: 'ПОЛ-013' },
  { time: '12.06 11:05', user: 'Иванов С.П.', action: 'Вход в систему', object: 'ivanov.sp · АРМ-2847 · VPN', policy: 'ПОЛ-005' }
];

const adminAuditLogFunc = [
  { time: '14.06 15:10', user: 'Козлов В.А.', action: 'Просмотр журнала', object: 'фильтр · пользователь petrov.a', policy: 'ПОЛ-004' },
  { time: '14.06 11:42', user: 'Козлов В.А.', action: 'Создание УЗ', object: 'petrov.a · следователь', policy: 'ПОЛ-009' },
  { time: '14.06 10:15', user: 'Козлов В.А.', action: 'Назначение роли', object: 'sidorova.m · аналитик', policy: 'ПОЛ-009' },
  { time: '14.06 09:30', user: 'Козлов В.А.', action: 'Разблокировка УЗ', object: 'garifullin.r · 3 неудачных входа', policy: 'ПОЛ-009' },
  { time: '13.06 16:30', user: 'Козлов В.А.', action: 'Блокировка', object: 'kozlov.v · увольнение', policy: 'ПОЛ-009' },
  { time: '13.06 14:02', user: 'Козлов В.А.', action: 'Согласование заявки', object: 'Иванов С.П. · перевод в отдел', policy: 'ПОЛ-009' },
  { time: '13.06 11:20', user: 'Козлов В.А.', action: 'Сброс пароля', object: 'morozova.e · по заявке руководителя', policy: 'ПОЛ-009' },
  { time: '12.06 16:45', user: 'Козлов В.А.', action: 'Экспорт отчёта', object: 'УЗ ведомства · 847 записей', policy: 'ПОЛ-004' },
  { time: '12.06 09:55', user: 'Козлов В.А.', action: 'Запрос изменения роли', object: 'матрица · следователь → руководитель', policy: 'ПОЛ-014' },
  { time: '11.06 14:10', user: 'Козлов В.А.', action: 'Создание УЗ', object: 'abramov.p · дознаватель', policy: 'ПОЛ-009' }
];

function getAdminAuditLogSource() {
  return getAdminKind() === 'func' ? adminAuditLogFunc : adminAuditLogTech;
}

function formatAuditUserLabel(user) {
  return user === 'system' ? 'система' : user;
}

function getAuditLogUsers(rows) {
  return [...new Set(rows.map(r => r.user))].sort((a, b) => {
    if (a === 'system') return 1;
    if (b === 'system') return -1;
    return formatAuditUserLabel(a).localeCompare(formatAuditUserLabel(b), 'ru');
  });
}

function getAuditLogActions(rows) {
  return [...new Set(rows.map(r => r.action))].sort((a, b) => a.localeCompare(b, 'ru'));
}

function filterAuditLogRows(rows) {
  let list = rows.slice();
  if (auditFilterUser) list = list.filter(r => r.user === auditFilterUser);
  if (auditFilterAction) list = list.filter(r => r.action === auditFilterAction);
  if (auditFilterPeriod === 'today') list = list.filter(r => r.time.startsWith('14.06'));
  else if (auditFilterPeriod === '7d') list = list.filter(r => {
    const day = parseInt(r.time.split(' ')[0].split('.')[0], 10);
    return day >= 8;
  });
  const q = auditFilterQuery.trim().toLowerCase();
  if (q) {
    list = list.filter(r =>
      formatAuditUserLabel(r.user).toLowerCase().includes(q) ||
      r.action.toLowerCase().includes(q) ||
      r.object.toLowerCase().includes(q) ||
      r.policy.toLowerCase().includes(q) ||
      r.time.includes(q)
    );
  }
  return list;
}

function onAuditFilterChange() {
  auditFilterUser = document.getElementById('audit-filter-user')?.value || '';
  auditFilterAction = document.getElementById('audit-filter-action')?.value || '';
  auditFilterPeriod = document.getElementById('audit-filter-period')?.value || 'all';
  resetTablePage('admin-audit');
  renderAdminModuleDetail('LOG');
}

function onAuditSearchInput(value) {
  auditFilterQuery = value;
  resetTablePage('admin-audit');
  renderAdminModuleDetail('LOG');
}

function setAuditUserFilter(user) {
  auditFilterUser = auditFilterUser === user ? '' : user;
  resetTablePage('admin-audit');
  renderAdminModuleDetail('LOG');
}

function resetAuditFilters() {
  auditFilterUser = '';
  auditFilterAction = '';
  auditFilterQuery = '';
  auditFilterPeriod = 'all';
  resetTablePage('admin-audit');
  renderAdminModuleDetail('LOG');
}

function renderAdminAuditLogPanel() {
  tablePageRefresh['admin-audit'] = () => renderAdminModuleDetail('LOG');
  const kind = getAdminKind();
  const source = getAdminAuditLogSource();
  const filtered = filterAuditLogRows(source);
  const users = getAuditLogUsers(source);
  const actions = getAuditLogActions(source);
  const scopeNote = kind === 'func'
    ? 'Учётные записи и права · только ведомство · ПОЛ-008'
    : 'Все действия пользователей · метаданные без содержимого дел · ПОЛ-004';

  const userOptions = `<option value="">Все пользователи</option>` +
    users.map(u => `<option value="${escapeHtml(u)}" ${auditFilterUser === u ? 'selected' : ''}>${escapeHtml(formatAuditUserLabel(u))}</option>`).join('');
  const actionOptions = `<option value="">Все действия</option>` +
    actions.map(a => `<option value="${escapeHtml(a)}" ${auditFilterAction === a ? 'selected' : ''}>${escapeHtml(a)}</option>`).join('');

  const topUsers = users
    .filter(u => u !== 'system')
    .sort((a, b) => source.filter(r => r.user === b).length - source.filter(r => r.user === a).length)
    .slice(0, 6);
  const userChips = topUsers.map(u => {
    const count = source.filter(r => r.user === u).length;
    const active = auditFilterUser === u;
    return `<button type="button" class="audit-user-chip ${active ? 'active' : ''}" onclick="setAuditUserFilter('${escapeHtml(u)}')" title="${count} записей">${escapeHtml(formatAuditUserLabel(u))} <span class="audit-chip-count">${count}</span></button>`;
  }).join('');

  const summaryParts = [`Показано ${filtered.length} из ${source.length}`];
  if (auditFilterUser) summaryParts.push(`пользователь: ${formatAuditUserLabel(auditFilterUser)}`);
  if (auditFilterAction) summaryParts.push(`действие: ${auditFilterAction}`);
  if (auditFilterPeriod !== 'all') {
    summaryParts.push(auditFilterPeriod === 'today' ? 'период: сегодня' : 'период: 7 дней');
  }
  if (auditFilterQuery.trim()) summaryParts.push(`поиск: «${auditFilterQuery.trim()}»`);

  const meta = paginateList(filtered, 'admin-audit');
  const tableRows = meta.slice.length
    ? meta.slice.map(r => `<tr class="${auditFilterUser && r.user === auditFilterUser ? 'row-highlight' : ''}">
      <td class="audit-time-cell">${escapeHtml(r.time)}</td>
      <td><button type="button" class="audit-user-link" onclick="setAuditUserFilter('${escapeHtml(r.user)}')" title="Показать все действия пользователя">${escapeHtml(formatAuditUserLabel(r.user))}</button></td>
      <td>${escapeHtml(r.action)}</td>
      <td>${escapeHtml(r.object)}</td>
      <td><span class="muted">${escapeHtml(r.policy)}</span></td>
    </tr>`).join('')
    : `<tr><td colspan="5" class="muted audit-empty-cell">${source.length ? 'Нет записей по выбранным фильтрам · измените условия поиска' : 'Нет записей'}</td></tr>`;

  return `<p class="muted audit-scope-note">${scopeNote}</p>
    <div class="audit-toolbar">
      <label class="audit-search-field">
        <span class="sr-only">Поиск по журналу</span>
        <input type="search" id="audit-search" class="audit-search-input" placeholder="Поиск: пользователь, действие, объект, политика, время…" value="${escapeHtml(auditFilterQuery)}" oninput="onAuditSearchInput(this.value)">
      </label>
      <div class="audit-filters">
        <label class="field audit-filter-field">
          <span>Пользователь</span>
          <select id="audit-filter-user" onchange="onAuditFilterChange()">${userOptions}</select>
        </label>
        <label class="field audit-filter-field">
          <span>Действие</span>
          <select id="audit-filter-action" onchange="onAuditFilterChange()">${actionOptions}</select>
        </label>
        <label class="field audit-filter-field audit-filter-period">
          <span>Период</span>
          <select id="audit-filter-period" onchange="onAuditFilterChange()">
            <option value="all" ${auditFilterPeriod === 'all' ? 'selected' : ''}>Все записи</option>
            <option value="today" ${auditFilterPeriod === 'today' ? 'selected' : ''}>Сегодня</option>
            <option value="7d" ${auditFilterPeriod === '7d' ? 'selected' : ''}>7 дней</option>
          </select>
        </label>
        <button type="button" class="btn-sm audit-reset-btn" onclick="resetAuditFilters()">Сбросить</button>
      </div>
      <div class="audit-user-chips">
        <span class="audit-chips-label">Быстрый выбор пользователя:</span>
        ${userChips}
      </div>
      <p class="audit-filter-summary muted">${escapeHtml(summaryParts.join(' · '))}</p>
    </div>
    <div class="paginated-table-body">
      <div class="table-scroll table-scroll-paged"><table class="data-table audit-log-table"><thead><tr><th>Время</th><th>Пользователь</th><th>Действие</th><th>Объект</th><th>Политика</th></tr></thead><tbody>
        ${tableRows}
      </tbody></table></div>
      ${renderTablePagination(meta)}
    </div>
    <p class="muted audit-foot-note">Append-only · WORM · хранение 7 лет · экспорт только с ПОЛ-004 · клик по пользователю — фильтр по его действиям</p>`;
}

function renderAdminSessionsTableHtml() {
  tablePageRefresh['admin-sessions'] = () => renderAdminModuleDetail('SES');
  const sessions = getAllActiveSessions();
  const meta = paginateList(sessions, 'admin-sessions');
  const tableRows = meta.slice.length
    ? meta.slice.map(s => `<tr>
        <td><code>${s.sessionId}</code></td>
        <td>${escapeHtml(s.name)}<br><span class="muted">${escapeHtml(s.login)}</span></td>
        <td>${escapeHtml(s.agency)}</td>
        <td>${escapeHtml(s.contour)}</td>
        <td>${escapeHtml(s.client || '—')}<br><span class="muted">${escapeHtml(s.ip || '—')}</span></td>
        <td>${escapeHtml(s.region)}</td>
        <td>${escapeHtml(s.vpn)}</td>
        <td class="muted">${escapeHtml(s.userAgent || '—')}</td>
      </tr>`).join('')
    : '<tr><td colspan="8" class="muted">Нет активных сессий</td></tr>';
  return `<div class="paginated-table-body">
    <div class="table-scroll table-scroll-paged"><table class="data-table"><thead><tr><th>Сессия</th><th>Пользователь</th><th>Ведомство</th><th>Контур</th><th>АРМ / IP</th><th>Регион</th><th>VPN</th><th>Клиент</th></tr></thead><tbody>
      ${tableRows}
    </tbody></table></div>
    ${renderTablePagination(meta)}
  </div>`;
}

function renderAdmin() {
  ensureAdminModuleAllowed();
  renderAdminNav();
  renderAdminModuleDetail(activeAdminModule);
  updateAdminKpis();
  updateAdminContext();
}

function updateAdminContext() {
  const ctx = document.getElementById('admin-context');
  if (!ctx) return;
  const kind = getAdminKind();
  if (kind === 'func') {
    const scope = getActivePersona().adminAgencyScope || 'ведомство';
    ctx.textContent = `${scope} · учётные записи и доступы · ПОЛ-008: без содержимого дел`;
  } else {
    ctx.textContent = 'Контур ЦОД · инфраструктура · ПОЛ-008: без содержимого дел';
  }
}

function countOnlineSessions() {
  return Object.keys(demoPersonas).filter(id => getPresence(id).online).length;
}

function updateAdminKpis() {
  const onlineEl = document.getElementById('admin-kpi-online');
  const svcEl = document.getElementById('admin-kpi-svc');
  const queueEl = document.getElementById('admin-kpi-queue');
  const labelOnline = document.getElementById('admin-kpi-label-online');
  const labelSvc = document.getElementById('admin-kpi-label-svc');
  const labelQueue = document.getElementById('admin-kpi-label-queue');
  const kind = getAdminKind();

  if (kind === 'func') {
    if (onlineEl) onlineEl.textContent = '3';
    if (svcEl) svcEl.textContent = '12';
    if (queueEl) queueEl.textContent = '8';
    if (labelOnline) labelOnline.textContent = 'заявок на УЗ';
    if (labelSvc) labelSvc.textContent = 'ролей';
    if (labelQueue) labelQueue.textContent = 'действий сегодня';
    return;
  }

  if (onlineEl) onlineEl.textContent = String(countOnlineSessions());
  if (svcEl) svcEl.textContent = `${adminServices.filter(s => s.status === 'healthy').length}/${adminServices.length}`;
  if (queueEl) queueEl.textContent = String(adminIntegrations.reduce((sum, i) => sum + i.queue, 0));
  if (labelOnline) labelOnline.textContent = 'в сети';
  if (labelSvc) labelSvc.textContent = 'сервисов';
  if (labelQueue) labelQueue.textContent = 'очередь СМЭВ';
}

function renderAdminNav() {
  const nav = document.getElementById('admin-nav');
  if (!nav) return;
  const onlineCount = countOnlineSessions();
  const modules = getAdminModulesForPersona();
  nav.innerHTML = modules.map(m => {
    const badge = m.id === 'SES' ? onlineCount : m.badge;
    return `<button type="button" class="admin-nav-item ${activeAdminModule === m.id ? 'active' : ''}"
      style="--adm-color:${m.color}" onclick="selectAdminModule('${m.id}')">
      <span class="admin-nav-icon">${m.icon}</span>
      <span class="admin-nav-text">
        <span class="admin-nav-name">${m.name}</span>
        <span class="admin-nav-desc">${m.summary}</span>
      </span>
      ${badge != null ? `<span class="admin-nav-badge">${badge}</span>` : ''}
    </button>`;
  }).join('');
}

function renderAdminModulesGrid() {
  renderAdminNav();
}

function selectAdminModule(id) {
  activeAdminModule = id;
  if (id === 'LOG') resetTablePage('admin-audit');
  if (id === 'SES') resetTablePage('admin-sessions');
  renderAdmin();
}

function renderAdminModuleDetail(id) {
  const el = document.getElementById('admin-module-detail');
  if (!el) return;
  const mod = adminModules.find(m => m.id === id);
  if (!mod) return;
  let body = '';
  let actions = '';
  const policyNote = getAdminKind() === 'func'
    ? 'ПОЛ-008: без доступа к делам · только УЗ и права ведомства'
    : 'ПОЛ-008: без доступа к делам · инфраструктура платформы';

  if (id === 'SVC') {
    body = `<div class="table-scroll"><table class="data-table"><thead><tr><th>Сервис</th><th>Статус</th><th>Экземпляры</th><th>Время отклика (P99)</th><th>Версия</th></tr></thead><tbody>
      ${adminServices.map(s => `<tr><td>${serviceNames[s.id] || s.id}</td><td><span class="status ${s.status === 'healthy' ? 'fulfilled' : 'progress'}">${adminStatusLabel(s.status)}</span></td><td>${s.ready}/${s.desired}</td><td>${s.p99} мс</td><td>${s.version}</td></tr>`).join('')}
    </tbody></table></div>`;
    actions = '<button type="button" class="btn-sm" onclick="adminRefreshMetrics()">↻ Обновить метрики</button>';
  } else if (id === 'SES') {
    body = renderAdminSessionsTableHtml();
    actions = '<button type="button" class="btn-sm" onclick="adminRefreshSessions()">↻ Обновить сессии</button>';
  } else if (id === 'STR') {
    body = renderAdminStructuresPanel();
  } else if (id === 'USR') {
    body = renderUserAccountsPanel();
    actions = '<p class="muted" style="font-size:0.8rem">ПОЛ-009: заявки от руководителей · согласование кадрами ведомства</p>';
  } else if (id === 'ROL') {
    body = `<div class="table-scroll"><table class="data-table"><thead><tr><th>Роль</th><th>Дела</th><th>Граф</th><th>Запросы</th><th>Кадры</th><th>Назначено</th></tr></thead><tbody>
      <tr><td>Следователь</td><td>✓</td><td>✓</td><td>✓</td><td>—</td><td>847</td></tr>
      <tr><td>Руководитель СО</td><td>✓</td><td>✓</td><td>✓</td><td>✓</td><td>124</td></tr>
      <tr><td>Оперуполномоченный</td><td>✓</td><td>✓</td><td>✓</td><td>—</td><td>312</td></tr>
      <tr><td>Управление ИТ</td><td>—</td><td>—</td><td>—</td><td>✓</td><td>4</td></tr>
    </tbody></table></div>
    <p class="muted" style="margin-top:0.75rem;font-size:0.8rem">Изменение матрицы — согласование с тех. админом (ПОЛ-014)</p>`;
    actions = '<button type="button" class="btn-sm" onclick="adminNewProvision()">Запросить изменение роли</button>';
  } else if (id === 'PPL') {
    body = renderAdminStructuresPanel();
  } else if (id === 'LOG') {
    body = renderAdminAuditLogPanel();
    actions = getAdminKind() === 'tech'
      ? '<button type="button" class="btn-sm" onclick="adminExportAudit()">Экспорт в SIEM</button><button type="button" class="btn-sm" onclick="adminRefreshAudit()">↻ Обновить</button>'
      : '';
  } else if (id === 'INT') {
    body = `<div class="table-scroll"><table class="data-table"><thead><tr><th>Адаптер</th><th>Статус</th><th>Очередь</th><th>Серт. до</th><th></th></tr></thead><tbody>
      ${adminIntegrations.map(i => `<tr><td>${i.agency}</td><td><span class="status ${i.status === 'online' ? 'fulfilled' : 'progress'}">${adminStatusLabel(i.status)}</span></td><td>${i.queue}</td><td>${i.cert}</td><td>${i.status === 'cert_expiring' ? '<button class="btn-xs approve" onclick="adminRotateCert()">Ротация</button>' : ''}</td></tr>`).join('')}
    </tbody></table></div>`;
  } else if (id === 'CFG') {
    body = `<div class="table-scroll"><table class="data-table"><thead><tr><th>Функция</th><th>Область</th><th>Включён</th></tr></thead><tbody>
      <tr><td>osint.enabled</td><td>пробная эксплуатация: 23, 77, 16</td><td><input type="checkbox" checked disabled></td></tr>
      <tr><td>horizon.enabled</td><td>пробная эксплуатация: 23, 77</td><td><input type="checkbox" checked disabled></td></tr>
      <tr><td>graph.community_detection</td><td>глобально</td><td><input type="checkbox" checked disabled></td></tr>
    </tbody></table></div>`;
    actions = '<button type="button" class="btn-sm" onclick="adminSaveFlags()">Сохранить (ПОЛ-014)</button>';
  } else if (id === 'OSW') {
    const osintWhitelistModules = ['sfp_dnsresolve', 'sfp_email', 'sfp_phone', 'sfp_spider', 'sfp_webanalyze'];
    body = `<div class="admin-config-block">
      <p><strong>Кластер исполнителей:</strong> 4 экземпляра (мин. 2, макс. 10)</p>
      <p><strong>Перечень разрешённых модулей:</strong> ${osintWhitelistModules.map(osintModuleLabel).join(', ')}</p>
      <p><strong>Политика прокси:</strong> строгая</p>
      <p class="muted">Изменение перечня → двойной контроль (тех. админ + управление ИТ ведомства)</p>
    </div>`;
    actions = '<button type="button" class="btn-sm" onclick="adminScaleWorkers()">Масштаб +1</button><button type="button" class="btn-sm" onclick="adminWhitelistDiff()">Запрос изменения списка</button>';
  } else if (id === 'HZM') {
    body = `<div class="admin-config-block">
      <p><strong>Модули:</strong> совпадения ✓ скрытые связи ✓ пересечения ✓ кластер ✓ двойник ✓ прогноз ✓ идентификация ✓</p>
      <p><strong>Индекс совпадений:</strong> <span class="status fulfilled">${adminStatusLabel('healthy')}</span> · 12 847 записей · пересборка 01.06.2028</p>
    </div>`;
    actions = '<button type="button" class="btn-sm" onclick="adminRebuildBloom()">↻ Пересобрать индекс</button><button type="button" class="btn-sm" onclick="adminToggleHorizonModule()">Переключить идентификацию (проверка)</button>';
  } else if (id === 'OPS') {
    body = `<div class="table-scroll"><table class="data-table"><thead><tr><th>Задача</th><th>Тип</th><th>Пробный прогон</th><th>Запланировано</th><th>Статус</th></tr></thead><tbody>
      <tr><td>job-8841</td><td>очистка откр. источников</td><td>да</td><td>15.06.2028 02:00</td><td><span class="status progress">${adminStatusLabel('scheduled')}</span></td></tr>
      <tr><td>job-8839</td><td>ротация ключей</td><td>нет</td><td>10.06.2028</td><td><span class="status fulfilled">${adminStatusLabel('completed')}</span></td></tr>
    </tbody></table></div>
    <div class="admin-config-block" style="margin-top:1rem">
      <p><strong>Обслуживание:</strong> 22.06.2028 01:00–03:00 · сервисы управления откр. источников и «Горизонт»</p>
    </div>`;
    actions = '<button type="button" class="btn-sm" onclick="adminSchedulePurge()">Запланировать очистку</button><button type="button" class="btn-sm" onclick="adminMaintenanceWindow()">+ Окно обслуживания</button>';
  }

  el.innerHTML = `
    <div class="panel adm-detail-panel">
      <div class="panel-header"><h2><span class="adm-detail-id">${mod.id}</span> ${mod.name}</h2></div>
      <p class="muted adm-detail-desc">${mod.summary} · ${policyNote}</p>
      <div class="adm-detail-body">${body}</div>
      ${actions ? `<div class="ha-actions">${actions}</div>` : ''}
    </div>`;
}

function renderAdminStructuresPanel() {
  return renderStructuresPanel();
}

function selectAdminStructure(label) {
  if (!label || activeStaffStructure === label) return;
  activeStaffStructure = label;
  expandedStructurePersona = null;
  resetTablePage('structures');
  if (document.getElementById('structures-layout')) {
    refreshStructuresPanel();
    return;
  }
  if (activeAdminModule === 'STR' || activeAdminModule === 'PPL') renderAdminModuleDetail(activeAdminModule);
  if (document.getElementById('view-staff')?.classList.contains('active')) renderStaff();
}

function renderStructuresAgencyNav() {
  return getStructuresAgencyGroups().map(g => {
    const online = g.ids.filter(id => getPresence(id).online).length;
    const active = activeStaffStructure === g.label ? ' active' : '';
    return `<button type="button" class="structure-agency-btn${active}" data-structure-agency="${escapeHtml(g.label)}">
      <span class="structure-agency-btn-name">${escapeHtml(g.label)}</span>
      <span class="structure-agency-btn-count">${online}/${g.ids.length}</span>
    </button>`;
  }).join('');
}

function renderStructuresMainContent() {
  tablePageRefresh.structures = refreshStructuresPanel;
  const groups = getStructuresAgencyGroups();
  const group = groups.find(g => g.label === activeStaffStructure) || groups[0] || demoPersonaGroups[0];
  const ids = group?.ids || [];
  const onlineCount = ids.filter(id => getPresence(id).online).length;
  const offlineCount = ids.length - onlineCount;
  const simple = structuresUseSimpleCards();
  const meta = paginateList(ids, 'structures');
  const rows = meta.slice.map(id => renderStructurePersonRow(id, simple)).join('');

  const tableHead = simple
    ? `<tr><th class="st-col-status"></th><th>Сотрудник</th><th>Отдел</th><th>Регион</th><th>Роль</th><th class="st-col-mail">Почта</th></tr>`
    : `<tr><th class="st-col-status"></th><th>Сотрудник</th><th>Отдел</th><th>Контур</th><th>Подключение</th><th class="st-col-action"></th></tr>`;

  const tableBody = rows || `<tr><td colspan="${simple ? 6 : 6}" class="muted structures-empty">Нет сотрудников в этом ведомстве</td></tr>`;

  return `
    <header class="structures-agency-header">
      <div class="structures-agency-title-wrap">
        <h3 id="structures-agency-title">${escapeHtml(group?.label || '—')}</h3>
        <p class="muted">${simple ? 'Состав ведомства' : 'Сотрудники · сессии и контуры'}</p>
      </div>
      <div class="structures-agency-stats">
        <span class="structures-stat online"><strong>${onlineCount}</strong> в сети</span>
        <span class="structures-stat offline"><strong>${offlineCount}</strong> офлайн</span>
        <span class="structures-stat total"><strong>${ids.length}</strong> всего</span>
      </div>
    </header>
    <div class="structures-table-wrap paginated-table-body">
      <div class="table-scroll table-scroll-paged">
      <table class="data-table structures-table">
        <thead>${tableHead}</thead>
        <tbody id="structure-rows-body">${tableBody}</tbody>
      </table>
      </div>
      ${renderTablePagination(meta)}
    </div>`;
}

function toggleStructureExpand(personaId) {
  expandedStructurePersona = expandedStructurePersona === personaId ? null : personaId;
  refreshStructuresPanel();
}

function refreshStructuresPanel() {
  const nav = document.getElementById('structures-agency-nav');
  const main = document.getElementById('structures-main');
  if (!main) {
    if (activeAdminModule === 'STR' || activeAdminModule === 'PPL') renderAdminModuleDetail(activeAdminModule);
    if (document.getElementById('view-staff')?.classList.contains('active')) renderStaff();
    return;
  }
  if (nav) nav.innerHTML = renderStructuresAgencyNav();
  main.innerHTML = renderStructuresMainContent();
}

function initStructuresNav() {
  if (document.body.dataset.structuresNavBound) return;
  document.body.dataset.structuresNavBound = '1';
  document.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-structure-agency]');
    if (!btn) return;
    e.preventDefault();
    selectAdminStructure(btn.getAttribute('data-structure-agency'));
  });
}

function renderStructureSessionSummary(pres) {
  if (pres.online) {
    const vpnOn = pres.vpn && pres.vpn !== 'нет' && !pres.vpn.startsWith('нет');
    return `<span class="st-session-line mono">${escapeHtml(pres.login)} · ${escapeHtml(pres.ip || '—')}</span>
      <span class="st-session-sub muted">${escapeHtml(pres.client || '—')} · ${escapeHtml(pres.sessionId || '—')}${vpnOn ? ' · <span class="structure-vpn-tag">VPN</span>' : ''}</span>`;
  }
  return `<span class="st-session-line muted">Последний вход: ${escapeHtml(pres.lastSeen)}</span>`;
}

function renderStructureSessionExpand(pres, personaId) {
  const vpnOn = pres.vpn && pres.vpn !== 'нет' && !pres.vpn.startsWith('нет');
  if (pres.online) {
    return `<div class="structure-session-compact">
      <div class="structure-session-grid">
        <div class="structure-session-item"><span class="structure-session-label">АРМ</span><span class="structure-session-value">${escapeHtml(pres.client)}</span></div>
        <div class="structure-session-item"><span class="structure-session-label">IP</span><span class="structure-session-value mono">${escapeHtml(pres.ip)}</span></div>
        <div class="structure-session-item"><span class="structure-session-label">Логин</span><span class="structure-session-value">${escapeHtml(pres.login)}</span></div>
        <div class="structure-session-item"><span class="structure-session-label">Клиент</span><span class="structure-session-value">${escapeHtml(pres.userAgent)}</span></div>
        <div class="structure-session-item"><span class="structure-session-label">ID сессии</span><span class="structure-session-value mono">${escapeHtml(pres.sessionId)}</span></div>
        <div class="structure-session-item"><span class="structure-session-label">ЕСИА</span><span class="structure-session-value mono">${escapeHtml(pres.cert)}</span></div>
        <div class="structure-session-item"><span class="structure-session-label">Почта</span><span class="structure-session-value">${corpMailLinkHtml(getCorporateEmail(personaId))}</span></div>
        ${vpnOn ? '<div class="structure-session-item"><span class="structure-session-label">VPN</span><span class="structure-session-value"><span class="structure-vpn-tag">активен</span></span></div>' : ''}
      </div>
    </div>`;
  }
  return `<div class="structure-session-compact structure-offline-compact">
    <div class="structure-offline-row">
      <span class="structure-offline-label">Последний вход</span>
      <span class="structure-offline-time">${escapeHtml(pres.lastSeen)}</span>
    </div>
    <div class="structure-offline-row">
      <span class="structure-offline-label">Почта</span>
      <span class="structure-offline-value">${corpMailLinkHtml(getCorporateEmail(personaId))}</span>
    </div>
  </div>`;
}

function renderStructurePersonRow(personaId, simple) {
  const rec = getPersonnelRecord(personaId);
  const pres = getPresence(personaId);
  const p = demoPersonas[personaId];
  if (!p) return '';
  const expanded = expandedStructurePersona === personaId;
  const corpEmail = getCorporateEmail(personaId);
  const personCell = `<div class="st-person">
    <span class="st-avatar">${escapeHtml(p.avatar)}</span>
    <div class="st-person-text">
      <strong>${escapeHtml(rec.name)}</strong>
      <span class="muted">${escapeHtml(rec.rank)}</span>
    </div>
  </div>`;

  if (simple) {
    return `<tr class="structure-row ${pres.online ? 'is-online' : 'is-offline'}">
      <td>${presenceDotHtml(pres.online)}</td>
      <td>${personCell}</td>
      <td class="st-dept">${escapeHtml(rec.department)}</td>
      <td class="muted">${escapeHtml(rec.region)}</td>
      <td><span class="structure-tag-sm">${escapeHtml(p.role)}</span></td>
      <td class="st-mail">${corpMailLinkHtml(corpEmail)}</td>
    </tr>`;
  }

  const expandBtn = `<button type="button" class="st-expand-btn${expanded ? ' open' : ''}" onclick="toggleStructureExpand('${personaId}')" aria-expanded="${expanded}" title="${expanded ? 'Свернуть' : 'Подробнее'}">${expanded ? '▴' : '▾'}</button>`;
  const mainRow = `<tr class="structure-row ${pres.online ? 'is-online' : 'is-offline'}${expanded ? ' is-expanded' : ''}">
    <td>${presenceDotHtml(pres.online)}</td>
    <td>${personCell}</td>
    <td class="st-dept muted">${escapeHtml(rec.department)}</td>
    <td><span class="structure-tag-sm">${escapeHtml(pres.contour)}</span><span class="st-region muted">${escapeHtml(rec.region)}</span></td>
    <td class="st-session">${renderStructureSessionSummary(pres)}</td>
    <td class="st-col-action">${expandBtn}</td>
  </tr>`;
  const expandRow = expanded
    ? `<tr class="structure-row-detail"><td colspan="6">${renderStructureSessionExpand(pres, personaId)}</td></tr>`
    : '';
  return mainRow + expandRow;
}

function renderStructuresPanel() {
  const groups = getStructuresAgencyGroups();
  const singleAgency = groups.length === 1;
  if (singleAgency) activeStaffStructure = groups[0].label;

  const sidebar = singleAgency ? '' : `<aside class="structures-sidebar">
      <p class="structures-sidebar-title">Ведомства</p>
      <nav class="structures-agency-nav" id="structures-agency-nav">${renderStructuresAgencyNav()}</nav>
    </aside>`;

  return `<div class="structures-layout${singleAgency ? ' structures-layout-single' : ''}" id="structures-layout">
    ${sidebar}
    <div class="structures-main" id="structures-main">${renderStructuresMainContent()}</div>
  </div>`;
}

function adminRefreshSessions() {
  showToast('Сессии: список обновлён.');
  if (document.getElementById('view-staff')?.classList.contains('active')) renderStaff();
  else renderAdminModuleDetail('SES');
}

function adminRefreshMetrics() { showToast('Мониторинг: метрики обновлены.'); renderAdminModuleDetail('SVC'); }
function adminNewProvision() { showToast('Учётные записи: заявка создана — на согласовании.'); }
function adminRotateCert() { showToast('Интеграции: ротация сертификата ФТС запланирована (ПОЛ-012).'); }
function adminSaveFlags() { showToast('Параметры функций сохранены, запись в журнал.'); }
function adminExportAudit() { showToast('Журнал аудита: экспорт в SIEM · admin.audit · 847 событий за 24 ч (ПОЛ-004).'); }
function adminRefreshAudit() { showToast('Журнал аудита: список обновлён.'); renderAdminModuleDetail('LOG'); }
function adminScaleWorkers() { showToast('Кластер сбора: 4 → 5 экземпляров (макс. 10).'); }
function adminWhitelistDiff() { showToast('Сбор ОИ: изменение перечня модулей отправлено на согласование.'); }
function adminRebuildBloom() { showToast('«Горизонт»: пересборка индекса совпадений запланирована.'); }
function adminToggleHorizonModule() { showToast('«Горизонт»: переключение модуля — проверка обслуживания.'); }
function adminSchedulePurge() { showToast('Операции: пробная очистка — 15.06.2028 02:00.'); }
function adminMaintenanceWindow() { showToast('Операции: окно обслуживания создано, уведомление пользователей.'); }

// --- Presence / сессии ---

const PRESENCE_ONLINE_IDS = new Set([
  'INV_MVD', 'INV_LEAD_MVD', 'TECH_ADMIN', 'INV_SK', 'ANALYST', 'EXEC_MVD', 'INV_FSB', 'PROSEC'
]);

const PRESENCE_LOGIN_MAP = {
  INV_MVD: 'ivanov.sp',
  INV_LEAD_MVD: 'morozova.ea',
  TECH_ADMIN: 'sidorov.av',
  FUNC_ADMIN: 'kozlov.va',
  INV_SK: 'petrova.ak',
  OPS_MVD: 'sidorov.mv',
  INV_FSB: 'volkov.ia'
};

let presenceState = {};

function personaIdToLogin(personaId) {
  return PRESENCE_LOGIN_MAP[personaId] || personaId.toLowerCase().replace(/_/g, '.');
}

function getCorporateEmail(personaId) {
  return `${personaIdToLogin(personaId)}@epsok.gov.ru`;
}

function buildDefaultPresence(personaId) {
  const p = demoPersonas[personaId];
  if (!p) return { online: false, lastSeen: '—' };
  const hash = [...personaId].reduce((a, c) => a + c.charCodeAt(0), 0);
  const online = PRESENCE_ONLINE_IDS.has(personaId) || (hash % 7 === 0);
  const hour = 8 + hash % 4;
  const min = 10 + hash % 40;
  return {
    online,
    lastSeen: online ? 'сейчас' : `сегодня ${hour}:${String(min).padStart(2, '0')}`,
    ip: online ? `10.${20 + hash % 40}.${hash % 255}.${10 + hash % 200}` : null,
    client: online ? `АРМ · ${(p.department || p.group || 'ЕПСОК').slice(0, 32)}` : null,
    region: p.region || '—',
    contour: p.headerContour || '—',
    login: personaIdToLogin(personaId),
    cert: `ESIA-${(hash % 9000) + 10000}`,
    sessionId: online ? `SES-${88400 + hash % 999}` : null,
    userAgent: online ? 'EPSOK Desktop 3.2.1' : null,
    vpn: personaId === 'TECH_ADMIN' ? 'да (тех. туннель)' : online && hash % 4 === 0 ? 'да' : 'нет'
  };
}

function getPresence(personaId) {
  if (!presenceState[personaId]) {
    presenceState[personaId] = buildDefaultPresence(personaId);
  }
  return presenceState[personaId];
}

function getAllActiveSessions() {
  return Object.keys(demoPersonas)
    .map(id => {
      const pres = getPresence(id);
      if (!pres.online) return null;
      const p = demoPersonas[id];
      return {
        personaId: id,
        name: p.name,
        agency: p.group,
        contour: pres.contour,
        region: pres.region,
        client: pres.client,
        ip: pres.ip,
        login: pres.login,
        sessionId: pres.sessionId,
        vpn: pres.vpn,
        userAgent: pres.userAgent
      };
    })
    .filter(Boolean)
    .sort((a, b) => a.name.localeCompare(b.name, 'ru'));
}

function presenceDotHtml(online, title) {
  const t = title || (online ? 'В сети' : 'Не в сети');
  return `<span class="presence-dot ${online ? 'online' : 'offline'}" title="${escapeHtml(t)}"></span>`;
}

function presenceBadgeHtml(pres) {
  return `<span class="presence-badge ${pres.online ? 'online' : 'offline'}">${pres.online ? '● В сети' : '○ Не в сети'}</span>`;
}

// --- Кадры: личная карточка, переводы, звания, выговоры ---

const HR_STORAGE_KEY = 'epsok-hr-state';

const HR_REQUEST_TYPES = {
  promotion: { label: 'Заявка · повышение звания', icon: '▲', short: 'Заявка · повышение' },
  transfer_dept: { label: 'Заявка · перевод в отдел', icon: '⇄', short: 'Заявка · перевод в отдел' },
  transfer_region: { label: 'Заявка · перевод в регион', icon: '◎', short: 'Заявка · перевод в регион' },
  transfer_agency: { label: 'Заявка · перевод в ведомство', icon: '▣', short: 'Заявка · перевод в ведомство' }
};

const HR_STATUS_LABELS = {
  submitted: 'На согласовании',
  manager_ok: 'Согласовано руководителем',
  manager_no: 'Отклонено руководителем',
  hr_ok: 'Утверждено кадрами',
  applied: 'Исполнено',
  rejected: 'Отклонено'
};

const DISCIPLINE_LABELS = {
  remark: 'Замечание',
  reprimand: 'Выговор',
  encouragement: 'Поощрение'
};

const RANK_LADDERS = {
  MVD: ['Младший лейтенант полиции', 'Лейтенант полиции', 'Старший лейтенант полиции', 'Капитан полиции', 'Майор полиции'],
  SK: ['Младший лейтенант юстиции', 'Лейтенант юстиции', 'Старший лейтенант юстиции', 'Капитан юстиции', 'Майор юстиции'],
  FSB: ['Младший лейтенант', 'Лейтенант', 'Старший лейтенант', 'Капитан', 'Майор'],
  default: ['Младший специалист', 'Специалист', 'Ведущий специалист', 'Главный специалист']
};

const TRANSFER_REGIONS = ['Краснодарский край', 'Ростовская область', 'Ставропольский край', 'Москва', 'Республика Татарстан'];
const TRANSFER_DEPTS_MVD = ['СО №1 по Прикубанскому району', 'СО №3 по Центральному району', 'СО №7 по Западному округу', 'ОУР №4', 'ОУР №2'];
const TRANSFER_AGENCIES = ['МВД России', 'СК России', 'Росгвардия', 'ФТС России'];

const personnelSeed = {
  INV_MVD: {
    tabNumber: 'КД-0002847',
    rank: 'Старший лейтенант полиции',
    position: 'Следователь следственного отдела',
    managerId: 'INV_LEAD_MVD',
    hireDate: '15.03.2024',
    rankDate: '12.01.2027',
    birthDate: '14.03.1989',
    phone: '+7 918 234-56-47',
    education: 'Кубанский ГУ МВД РФ · юриспруденция',
    merits: 2,
    history: [
      { date: '15.03.2024', kind: 'hire', text: 'Назначение в СО №3 · младший лейтенант полиции' },
      { date: '01.09.2025', kind: 'transfer', text: 'Перевод из дознавания в следственный отдел' },
      { date: '12.01.2027', kind: 'promotion', text: 'Присвоено звание старший лейтенант полиции' }
    ],
    disciplinary: [
      { date: '08.2027', kind: 'remark', issuer: 'Морозова Е.А.', text: 'Нарушение срока представления отчёта' }
    ]
  },
  INV_LEAD_MVD: {
    tabNumber: 'КД-0001204',
    rank: 'Подполковник полиции',
    position: 'Руководитель следственного отдела',
    managerId: null,
    hireDate: '20.06.2012',
    rankDate: '03.11.2024',
    birthDate: '02.07.1978',
    phone: '+7 861 210-45-88',
    education: 'Академия МВД РФ · право и управление',
    merits: 5,
    history: [
      { date: '20.06.2012', kind: 'hire', text: 'Назначение следователем ГСУ' },
      { date: '14.02.2020', kind: 'transfer', text: 'Перевод в Краснодарский край' },
      { date: '03.11.2024', kind: 'promotion', text: 'Присвоено звание подполковник полиции' }
    ],
    disciplinary: []
  },
  OPS_MVD: {
    tabNumber: 'КД-0003102',
    rank: 'Лейтенант полиции',
    position: 'Оперуполномоченный',
    managerId: 'OPS_LEAD_MVD',
    hireDate: '10.01.2025',
    rankDate: '10.01.2025',
    birthDate: '19.11.1996',
    phone: '+7 865 412-33-09',
    education: 'Ставропольский филиал ГУ МВД',
    merits: 0,
    history: [{ date: '10.01.2025', kind: 'hire', text: 'Назначение в ОУР №4 · Ставропольский край' }],
    disciplinary: []
  },
  OPS_LEAD_MVD: {
    tabNumber: 'КД-0000988',
    rank: 'Майор полиции',
    position: 'Руководитель оперативно-розыскной части',
    managerId: null,
    hireDate: '03.04.2010',
    rankDate: '18.08.2023',
    merits: 4,
    history: [
      { date: '03.04.2010', kind: 'hire', text: 'Назначение в ОУР · Ставропольский край' },
      { date: '18.08.2023', kind: 'promotion', text: 'Присвоено звание майор полиции' }
    ],
    disciplinary: []
  },
  INV_SK: {
    tabNumber: 'КД-0000891',
    rank: 'Капитан юстиции',
    position: 'Следователь следственного управления',
    managerId: 'INV_LEAD_SK',
    hireDate: '05.09.2018',
    rankDate: '22.04.2026',
    merits: 3,
    history: [{ date: '05.09.2018', kind: 'hire', text: 'Назначение в СУ по ЮВАО · Москва' }],
    disciplinary: []
  },
  INV_LEAD_SK: {
    tabNumber: 'КД-0000412',
    rank: 'Полковник юстиции',
    position: 'Руководитель следственного управления',
    managerId: null,
    hireDate: '12.02.2008',
    rankDate: '01.03.2025',
    merits: 6,
    history: [
      { date: '12.02.2008', kind: 'hire', text: 'Назначение следователем СУ по ЮВАО' },
      { date: '01.03.2025', kind: 'promotion', text: 'Присвоено звание полковник юстиции' }
    ],
    disciplinary: []
  },
  INV_FSB: {
    tabNumber: 'КД-Г-00412',
    rank: 'Майор',
    position: 'Следователь УФСБ',
    managerId: 'INV_LEAD_FSB',
    hireDate: '18.11.2016',
    rankDate: '30.08.2025',
    merits: 1,
    history: [{ date: '18.11.2016', kind: 'hire', text: 'Назначение в следственный отдел УФСБ' }],
    disciplinary: []
  },
  INV_MVD_NOVIKOV: {
    tabNumber: 'КД-0003018',
    rank: 'Лейтенант полиции',
    position: 'Следователь следственного отдела',
    managerId: 'INV_LEAD_MVD',
    hireDate: '01.06.2028',
    rankDate: '01.06.2028',
    birthDate: '22.09.1994',
    phone: '+7 918 301-22-18',
    education: 'Кубанский ГУ МВД РФ · юриспруденция',
    merits: 0,
    history: [{ date: '01.06.2028', kind: 'hire', text: 'Назначение в СО №2 · лейтенант полиции' }],
    disciplinary: []
  },
  INV_MVD_KOVALEV: {
    tabNumber: 'КД-0002901',
    rank: 'Старший лейтенант полиции',
    position: 'Следователь следственного отдела',
    managerId: 'INV_LEAD_MVD',
    hireDate: '12.08.2023',
    rankDate: '15.02.2027',
    birthDate: '07.01.1990',
    phone: '+7 918 290-11-01',
    education: 'Кубанский ГУ МВД РФ',
    merits: 1,
    history: [
      { date: '12.08.2023', kind: 'hire', text: 'Назначение в СО №3 · младший лейтенант полиции' },
      { date: '15.02.2027', kind: 'promotion', text: 'Присвоено звание старший лейтенант полиции' }
    ],
    disciplinary: []
  },
  INV_MVD_SEMYONOVA: {
    tabNumber: 'КД-0003188',
    rank: 'Лейтенант полиции',
    position: 'Следователь следственного отдела',
    managerId: 'INV_LEAD_MVD_WEST',
    hireDate: '20.01.2026',
    rankDate: '20.01.2026',
    birthDate: '18.05.1993',
    phone: '+7 918 318-88-20',
    education: 'Кубанский ГУ МВД РФ · юриспруденция',
    merits: 0,
    history: [{ date: '20.01.2026', kind: 'hire', text: 'Назначение в СО №7 · лейтенант полиции' }],
    disciplinary: []
  },
  INV_LEAD_MVD_WEST: {
    tabNumber: 'КД-0001156',
    rank: 'Майор полиции',
    position: 'Руководитель следственного отдела',
    managerId: 'INV_LEAD_MVD',
    hireDate: '14.03.2015',
    rankDate: '01.09.2024',
    birthDate: '11.12.1980',
    phone: '+7 861 318-55-12',
    education: 'Академия МВД РФ',
    merits: 3,
    history: [
      { date: '14.03.2015', kind: 'hire', text: 'Назначение следователем СО №7' },
      { date: '01.09.2024', kind: 'promotion', text: 'Присвоено звание майор полиции · руководитель СО' }
    ],
    disciplinary: []
  },
  INV_MVD_ROSTOV: {
    tabNumber: 'КД-0004022',
    rank: 'Капитан полиции',
    position: 'Следователь по особо важным делам',
    managerId: null,
    hireDate: '09.11.2019',
    rankDate: '20.03.2026',
    birthDate: '04.08.1986',
    phone: '+7 863 402-22-09',
    education: 'Ростовский филиал ГУ МВД',
    merits: 2,
    history: [{ date: '09.11.2019', kind: 'hire', text: 'Назначение в ОЭБ и ПК · Ростовская область' }],
    disciplinary: []
  },
  OPS_MVD_2: {
    tabNumber: 'КД-0003205',
    rank: 'Старший лейтенант полиции',
    position: 'Оперуполномоченный',
    managerId: 'OPS_LEAD_MVD',
    hireDate: '05.05.2022',
    rankDate: '05.05.2022',
    birthDate: '30.06.1992',
    phone: '+7 865 320-05-05',
    education: 'Ставропольский филиал ГУ МВД',
    merits: 1,
    history: [{ date: '05.05.2022', kind: 'hire', text: 'Назначение в ОУР №4 · Ставропольский край' }],
    disciplinary: []
  },
  OPS_MVD_3: {
    tabNumber: 'КД-0003211',
    rank: 'Лейтенант полиции',
    position: 'Оперуполномоченный',
    managerId: 'OPS_LEAD_MVD',
    hireDate: '18.09.2024',
    rankDate: '18.09.2024',
    birthDate: '14.02.1997',
    phone: '+7 865 321-11-18',
    education: 'Ставропольский филиал ГУ МВД',
    merits: 0,
    history: [{ date: '18.09.2024', kind: 'hire', text: 'Назначение в ОУР №4 · лейтенант полиции' }],
    disciplinary: []
  },
  INV_SK_2: {
    tabNumber: 'КД-0000912',
    rank: 'Старший лейтенант юстиции',
    position: 'Следователь следственного управления',
    managerId: 'INV_LEAD_SK',
    hireDate: '22.02.2021',
    rankDate: '10.10.2026',
    birthDate: '25.04.1991',
    phone: '+7 495 912-22-02',
    education: 'Академия следственного комитета',
    merits: 2,
    history: [{ date: '22.02.2021', kind: 'hire', text: 'Назначение в СУ по ЮВАО · Москва' }],
    disciplinary: []
  },
  INV_SK_3: {
    tabNumber: 'КД-0000933',
    rank: 'Лейтенант юстиции',
    position: 'Следователь следственного управления',
    managerId: 'INV_LEAD_SK',
    hireDate: '01.07.2025',
    rankDate: '01.07.2025',
    birthDate: '09.09.1995',
    phone: '+7 495 933-01-07',
    education: 'МГЮА · следственное право',
    merits: 0,
    history: [{ date: '01.07.2025', kind: 'hire', text: 'Назначение в СУ по ЮВАО · Москва' }],
    disciplinary: []
  },
  INV_LEAD_SK_ROSTOV: {
    tabNumber: 'КД-0000448',
    rank: 'Полковник юстиции',
    position: 'Руководитель следственного управления',
    managerId: null,
    hireDate: '03.03.2011',
    rankDate: '15.01.2025',
    birthDate: '16.06.1976',
    phone: '+7 863 448-03-03',
    education: 'Академия следственного комитета',
    merits: 4,
    history: [
      { date: '03.03.2011', kind: 'hire', text: 'Назначение следователем СУ · Ростов-на-Дону' },
      { date: '15.01.2025', kind: 'promotion', text: 'Присвоено звание полковник юстиции' }
    ],
    disciplinary: []
  },
  INV_SK_ROSTOV: {
    tabNumber: 'КД-0000877',
    rank: 'Капитан юстиции',
    position: 'Следователь следственного управления',
    managerId: 'INV_LEAD_SK_ROSTOV',
    hireDate: '11.02.2018',
    rankDate: '11.02.2023',
    birthDate: '28.11.1988',
    phone: '+7 863 877-11-02',
    education: 'Ростовский юридический институт',
    merits: 2,
    history: [{ date: '11.02.2018', kind: 'hire', text: 'Назначение в СУ по Ленинскому району' }],
    disciplinary: []
  },
  INV_LEAD_FSB: {
    tabNumber: 'КД-Г-00108',
    rank: 'Полковник',
    position: 'Руководитель следственного отдела УФСБ',
    managerId: null,
    hireDate: '01.04.2009',
    rankDate: '12.12.2023',
    birthDate: '03.02.1975',
    phone: '+7 861 108-01-04',
    education: 'Академия ФСБ России',
    merits: 5,
    history: [
      { date: '01.04.2009', kind: 'hire', text: 'Назначение в УФСБ по Краснодарскому краю' },
      { date: '12.12.2023', kind: 'promotion', text: 'Присвоено звание полковник · руководитель СО' }
    ],
    disciplinary: []
  },
  INV_FSB_2: {
    tabNumber: 'КД-Г-00428',
    rank: 'Капитан',
    position: 'Следователь УФСБ',
    managerId: 'INV_LEAD_FSB',
    hireDate: '15.07.2020',
    rankDate: '15.07.2024',
    birthDate: '21.03.1990',
    phone: '+7 861 428-15-07',
    education: 'Академия ФСБ России',
    merits: 1,
    history: [{ date: '15.07.2020', kind: 'hire', text: 'Назначение следователем УФСБ' }],
    disciplinary: []
  },
  INV_LEAD_RGV: {
    tabNumber: 'КД-РГ-00201',
    rank: 'Подполковник',
    position: 'Руководитель следственного подразделения',
    managerId: null,
    hireDate: '20.08.2013',
    rankDate: '01.05.2024',
    birthDate: '19.07.1979',
    phone: '+7 865 201-20-08',
    education: 'Военный университет Росгвардии',
    merits: 3,
    history: [
      { date: '20.08.2013', kind: 'hire', text: 'Назначение в Управление Росгвардии · Ставрополь' },
      { date: '01.05.2024', kind: 'promotion', text: 'Присвоено звание подполковник · руководитель' }
    ],
    disciplinary: []
  },
  INV_RGV: {
    tabNumber: 'КД-РГ-00314',
    rank: 'Майор',
    position: 'Следователь',
    managerId: 'INV_LEAD_RGV',
    hireDate: '10.04.2019',
    rankDate: '10.04.2023',
    merits: 1,
    history: [{ date: '10.04.2019', kind: 'hire', text: 'Назначение следователем Росгвардии · Ставропольский край' }],
    disciplinary: []
  },
  INV_RGV_2: {
    tabNumber: 'КД-РГ-00322',
    rank: 'Капитан',
    position: 'Следователь',
    managerId: 'INV_LEAD_RGV',
    hireDate: '01.02.2022',
    rankDate: '01.02.2026',
    birthDate: '13.10.1991',
    phone: '+7 865 322-01-02',
    education: 'Военный университет Росгвардии',
    merits: 0,
    history: [{ date: '01.02.2022', kind: 'hire', text: 'Назначение следователем · Управление Росгвардии' }],
    disciplinary: []
  },
  INV_LEAD_FTS: {
    tabNumber: 'КД-ТС-00088',
    rank: 'Главный государственный таможенный инспектор',
    position: 'Руководитель следственного отдела',
    managerId: null,
    hireDate: '06.06.2014',
    rankDate: '01.01.2025',
    birthDate: '08.04.1981',
    phone: '+7 495 088-06-06',
    education: 'РТА · таможенное дело',
    merits: 4,
    history: [
      { date: '06.06.2014', kind: 'hire', text: 'Назначение в Таможню Шереметьево' },
      { date: '01.01.2025', kind: 'promotion', text: 'Назначена руководителем следственного отдела' }
    ],
    disciplinary: []
  },
  INV_FTS: {
    tabNumber: 'КД-ТС-00142',
    rank: 'Государственный таможенный инспектор',
    position: 'Следователь таможни',
    managerId: 'INV_LEAD_FTS',
    hireDate: '12.03.2020',
    rankDate: '12.03.2024',
    merits: 2,
    history: [{ date: '12.03.2020', kind: 'hire', text: 'Назначение следователем · Таможня Шереметьево' }],
    disciplinary: []
  }
};

let personnelState = {};
let hrRequests = [];
let profileTab = 'card';
let staffTab = 'team';
let staffSelectedId = null;
let activeSuspectId = 'SUS-001';
let suspectSearchQuery = '';
let suspectFilterRegion = '';
let suspectFilterStatus = '';
let hrSeq = 1200;
let userAccountSeq = 500;
const userAccountRequestsSeed = [
  { id: 'УЗ-501', name: 'Новиков П.С.', rank: 'Лейтенант полиции', role: 'Следователь · СО №2', agency: 'МВД России', manager: 'Морозова Е.А.', region: 'Краснодарский край', basis: 'Приказ №118-ОД от 01.06.2028 о вводе должности', status: 'active', checks: 'Учётная запись создана · роли назначены' }
];
let userAccountRequests = [];

const suspectDossiersSeed = [
  {
    id: 'SUS-001',
    caseId: 'ЕПСОК-2028-004521',
    status: 'подозреваемый',
    lastName: 'Андреев',
    firstName: 'Сергей',
    patronymic: 'Викторович',
    birthDate: '15.04.1991',
    birthPlace: 'г. Краснодар',
    passport: '0315 284719',
    address: 'Краснодарский край, г. Краснодар, ул. Красная, 12',
    phones: '+7 918 452-67-89',
    emails: 'suspect.fraud@mail.ru',
    inn: '',
    measures: 'Подписка о невыезде',
    notes: 'Фигурант по ч. 3 ст. 159 УК. Связь с делом Москва по счёту.',
    updatedAt: '14.06.2028',
    updatedBy: 'Иванов С.П.'
  },
  {
    id: 'SUS-002',
    caseId: 'ЕПСОК-2028-004521',
    status: 'потерпевший',
    lastName: 'Громова',
    firstName: 'Елена',
    patronymic: 'Петровна',
    birthDate: '22.08.1975',
    birthPlace: 'г. Сочи',
    passport: '0318 901234',
    address: 'г. Краснодар, ул. Северная, 45',
    phones: '+7 918 111-22-33',
    emails: 'gromova.elena@mail.ru',
    inn: '',
    measures: '—',
    notes: 'Потерпевшая. Ущерб 847 000 ₽.',
    updatedAt: '14.01.2028',
    updatedBy: 'Иванов С.П.'
  },
  {
    id: 'SUS-003',
    caseId: 'ЕПСОК-2028-001234',
    status: 'подозреваемый',
    lastName: 'Козлов',
    firstName: 'Дмитрий',
    patronymic: 'Андреевич',
    birthDate: '03.11.1988',
    birthPlace: 'г. Москва',
    passport: '4512 667890',
    address: 'г. Москва, ул. Ленина, 8',
    phones: '+7 916 555-12-34',
    emails: 'kozlov.d@inbox.ru',
    inn: '7701234567',
    measures: 'Заключение под стражу',
    notes: 'Связь с делом Краснодар по счёту ***4521.',
    updatedAt: '05.02.2028',
    updatedBy: 'Петрова А.К.'
  },
  {
    id: 'SUS-004',
    caseId: 'ЕПСОК-2028-002891',
    status: 'обвиняемый',
    lastName: 'Мухин',
    firstName: 'Руслан',
    patronymic: 'Тимурович',
    birthDate: '19.07.1990',
    birthPlace: 'г. Казань',
    passport: '9215 334455',
    address: 'Республика Татарстан, г. Казань, ул. Баумана, 21',
    phones: '+7 (843) 567-88-99',
    emails: 'mukhin.rt@mail.ru',
    inn: '',
    measures: 'Подписка о невыезде',
    notes: 'Обвиняемый по делу Казань · связь по SIM с Краснодаром.',
    updatedAt: '10.03.2028',
    updatedBy: 'Волков И.Н.'
  },
  {
    id: 'SUS-005',
    caseId: 'ЕПСОК-2028-003891',
    status: 'свидетель',
    lastName: 'Лебедев',
    firstName: 'Олег',
    patronymic: 'Николаевич',
    birthDate: '02.12.1982',
    birthPlace: 'г. Краснодар',
    passport: '0310 778899',
    address: 'Краснодарский край, СО №3 · ул. Гимназическая, 5',
    phones: '+7 (918) 333-44-55',
    emails: 'lebedev.o@yandex.ru',
    inn: '',
    measures: '—',
    notes: 'Свидетель по делу СО №3 · показания по переводу.',
    updatedAt: '01.05.2028',
    updatedBy: 'Ковалёв Д.М.'
  },
  {
    id: 'SUS-006',
    caseId: 'ЕПСОК-2028-007501',
    status: 'подозреваемый',
    lastName: 'Зайцев',
    firstName: 'Павел',
    patronymic: 'Олегович',
    birthDate: '28.01.1987',
    birthPlace: 'г. Краснодар',
    passport: '0312 445566',
    address: 'г. Краснодар, ул. Садовая, 90',
    phones: '+7 (861) 422-33-44',
    emails: '',
    inn: '2310011223',
    measures: 'Запрет определённых действий',
    notes: 'Фигурант ФСБ · контур экономической безопасности.',
    updatedAt: '12.04.2028',
    updatedBy: 'Волков И.Н.'
  }
];

let suspectDossiers = [];

function getAgencyLadderKey(agency) {
  const a = agency || '';
  if (a.includes('МВД') || a === 'MVD') return 'MVD';
  if (a.includes('СК') || a === 'SK') return 'SK';
  if (a.includes('ФСБ') || a === 'FSB') return 'FSB';
  return 'default';
}

function userAccountRankOptionsHtml(agency) {
  const ladder = RANK_LADDERS[getAgencyLadderKey(agency)] || RANK_LADDERS.default;
  return ladder.map(r => `<option value="${escapeHtml(r)}">${escapeHtml(r)}</option>`).join('');
}

function updateUserAccountRankOptions() {
  const agency = document.getElementById('ua-agency')?.value;
  const rankEl = document.getElementById('ua-rank');
  if (!rankEl) return;
  const prev = rankEl.value;
  rankEl.innerHTML = userAccountRankOptionsHtml(agency || 'МВД России');
  if ([...rankEl.options].some(o => o.value === prev)) rankEl.value = prev;
}

function findRegionalManagerForPersona(personaId) {
  const p = demoPersonas[personaId];
  if (!p || isPersonnelManager(p)) return null;
  const match = Object.keys(demoPersonas).find(id => {
    if (id === personaId) return false;
    const m = demoPersonas[id];
    return isPersonnelManager(m) && m.agency === p.agency && m.region === p.region;
  });
  return match || null;
}

function isSamePersonnelRegion(personaA, personaB) {
  if (!personaA?.region || !personaB?.region) return true;
  return personaA.region === personaB.region;
}

function buildDefaultPersonnel(personaId) {
  const p = demoPersonas[personaId];
  if (!p) return null;
  const ladder = RANK_LADDERS[getAgencyLadderKey(p.agency)] || RANK_LADDERS.default;
  return {
    tabNumber: `КД-${String(1000 + personaId.length * 137).slice(-7)}`,
    rank: ladder[Math.min(2, ladder.length - 1)],
    position: p.role.split('·')[0].trim(),
    managerId: p.isManager ? null : findRegionalManagerForPersona(personaId),
    hireDate: '01.01.2026',
    rankDate: '01.01.2026',
    merits: 0,
    history: [{ date: '01.01.2026', kind: 'hire', text: `Назначение · ${p.department}` }],
    disciplinary: []
  };
}

function getPersonnelManagerName(managerId) {
  if (!managerId) return '—';
  return demoPersonas[managerId]?.name || '—';
}

function renderPersonnelAvatar(rec) {
  return `<div class="profile-avatar-lg profile-avatar-photo" aria-hidden="true">${escapeHtml(rec.avatar || '—')}</div>`;
}

function renderPersonnelHistoryList(rec) {
  const items = rec.history || [];
  if (!items.length) return '<li class="muted">Нет записей</li>';
  return items.map(h => `
    <li class="profile-history-item"><span class="profile-history-date">${escapeHtml(h.date)}</span><span>${escapeHtml(h.text)}</span></li>`).join('');
}

function renderPersonnelDisciplineList(rec, showMeta = true) {
  const items = rec.disciplinary || [];
  if (!items.length) return '<li class="muted">Нет</li>';
  return items.map(d => `<li class="profile-disc-item ${d.kind}">
    <span class="profile-disc-kind">${DISCIPLINE_LABELS[d.kind]}</span>
    ${showMeta ? `<span class="profile-disc-date">${escapeHtml(d.date)} · ${escapeHtml(d.issuer || '—')}</span>` : ''}
    <p>${escapeHtml(d.text)}</p></li>`).join('');
}

function renderPersonnelFactsExtended(rec, pres) {
  const email = getCorporateEmail(rec.personaId);
  const manager = getPersonnelManagerName(rec.managerId);
  const optional = (label, val) => val ? `<div><dt>${label}</dt><dd>${escapeHtml(val)}</dd></div>` : '';
  return `<dl class="profile-facts">
    <div><dt>Звание</dt><dd>${escapeHtml(rec.rank)}</dd></div>
    <div><dt>Дата звания</dt><dd>${escapeHtml(rec.rankDate || '—')}</dd></div>
    <div><dt>Должность</dt><dd>${escapeHtml(rec.position || '—')}</dd></div>
    <div><dt>Ведомство</dt><dd>${escapeHtml(rec.agencyName || '—')}</dd></div>
    <div><dt>Отдел</dt><dd>${escapeHtml(rec.department || '—')}</dd></div>
    <div><dt>Регион</dt><dd>${escapeHtml(rec.region || '—')}</dd></div>
    <div><dt>Табельный №</dt><dd>${escapeHtml(rec.tabNumber || '—')}</dd></div>
    <div><dt>На службе с</dt><dd>${escapeHtml(rec.hireDate || '—')}</dd></div>
    <div><dt>Корп. почта</dt><dd class="profile-mail-cell">${corpMailLinkHtml(email)}</dd></div>
    <div><dt>Руководитель</dt><dd>${escapeHtml(manager)}</dd></div>
    <div><dt>Поощрения</dt><dd>${rec.merits ?? 0}</dd></div>
    <div><dt>ЕСИА</dt><dd><code class="mono-sm">${escapeHtml(pres?.cert || '—')}</code></dd></div>
    ${optional('Дата рождения', rec.birthDate)}
    ${optional('Телефон', rec.phone)}
    ${optional('Образование', rec.education)}
  </dl>`;
}

function renderPersonnelPresenceRow(pres, fullPresence = false) {
  if (fullPresence) {
    return `<dl class="profile-facts presence-facts">
      <div><dt>Статус</dt><dd>${presenceBadgeHtml(pres)}</dd></div>
      <div><dt>Контур</dt><dd>${escapeHtml(pres.contour)}</dd></div>
      ${pres.online ? `
        <div><dt>АРМ</dt><dd>${escapeHtml(pres.client)}</dd></div>
        <div><dt>IP</dt><dd><code>${escapeHtml(pres.ip)}</code></dd></div>
        <div><dt>Логин</dt><dd>${escapeHtml(pres.login)}</dd></div>
        <div><dt>Сессия</dt><dd><code>${escapeHtml(pres.sessionId)}</code></dd></div>
        <div><dt>VPN</dt><dd>${escapeHtml(pres.vpn)}</dd></div>
        <div><dt>Клиент</dt><dd>${escapeHtml(pres.userAgent)}</dd></div>
      ` : `<div><dt>Последний вход</dt><dd>${escapeHtml(pres.lastSeen)}</dd></div>`}
    </dl>`;
  }
  return `<div class="presence-row">${presenceBadgeHtml(pres)}${!pres.online ? `<span class="muted"> · ${escapeHtml(pres.lastSeen)}</span>` : ''}</div>`;
}

async function loadHrState() {
  let data = null;
  if (typeof EpsokSecurity !== 'undefined') {
    data = await EpsokSecurity.secureGetItem(sessionStorage, HR_STORAGE_KEY);
    if (!data) data = await EpsokSecurity.secureGetItem(localStorage, HR_STORAGE_KEY);
  }
  if (!data) {
    try {
      const raw = sessionStorage.getItem(HR_STORAGE_KEY) || localStorage.getItem(HR_STORAGE_KEY);
      if (raw && !raw.startsWith('epsok:enc:')) data = JSON.parse(raw);
    } catch { /* demo */ }
  }
  if (data) {
    if (data.personnel) personnelState = data.personnel;
    if (data.requests) hrRequests = data.requests;
    if (data.hrSeq) hrSeq = data.hrSeq;
    if (data.suspects) suspectDossiers = data.suspects;
    if (data.userAccounts) userAccountRequests = data.userAccounts;
    if (data.userAccountSeq) userAccountSeq = data.userAccountSeq;
  }
  ensureSuspectDossiers();
  if (!userAccountRequests.length) userAccountRequests = JSON.parse(JSON.stringify(userAccountRequestsSeed));
}

function ensureSuspectDossiers() {
  if (!suspectDossiers.length) {
    suspectDossiers = JSON.parse(JSON.stringify(suspectDossiersSeed));
    return;
  }
  const ids = new Set(suspectDossiers.map(s => s.id));
  suspectDossiersSeed.forEach(s => {
    if (!ids.has(s.id)) suspectDossiers.push(JSON.parse(JSON.stringify(s)));
  });
}

async function saveHrState() {
  const data = { personnel: personnelState, requests: hrRequests, hrSeq, suspects: suspectDossiers, userAccounts: userAccountRequests, userAccountSeq };
  if (typeof EpsokSecurity !== 'undefined') {
    await EpsokSecurity.secureSetItem(sessionStorage, HR_STORAGE_KEY, data);
  } else {
    sessionStorage.setItem(HR_STORAGE_KEY, JSON.stringify(data));
  }
}

function getPersonnelRecord(personaId) {
  if (!personnelState[personaId]) {
    personnelState[personaId] = JSON.parse(JSON.stringify(
      personnelSeed[personaId] || buildDefaultPersonnel(personaId)
    ));
  }
  const p = demoPersonas[personaId];
  const rec = personnelState[personaId];
  if (!rec.department && p?.department) rec.department = p.department;
  if (!rec.region && p?.region) rec.region = p.region;
  if (!rec.agencyName && p?.group) rec.agencyName = p.group;
  if (!rec.agencyCode && p?.agency) rec.agencyCode = p.agency;
  if (rec.managerId && p && demoPersonas[rec.managerId] && !isSamePersonnelRegion(p, demoPersonas[rec.managerId])) {
    rec.managerId = findRegionalManagerForPersona(personaId);
    personnelState[personaId].managerId = rec.managerId;
  }
  return {
    ...rec,
    personaId,
    name: p?.name,
    agencyName: rec.agencyName || p?.group,
    agencyCode: rec.agencyCode || p?.agency,
    department: rec.department || p?.department,
    region: rec.region || p?.region,
    position: rec.position || p?.role?.split('·')[0]?.trim(),
    avatar: p?.avatar
  };
}

function isPersonnelManager(p) {
  return !!(p?.isManager || p?.roleType === 'inv_lead');
}

function getSubordinates(managerId) {
  const manager = demoPersonas[managerId];
  if (!manager) return [];
  return Object.keys(demoPersonas)
    .filter(id => {
      const rec = getPersonnelRecord(id);
      if (rec.managerId !== managerId) return false;
      return isSamePersonnelRegion(manager, demoPersonas[id]);
    })
    .map(id => getPersonnelRecord(id));
}

function canManagePersona(managerId, targetPersonaId) {
  if (managerId === targetPersonaId) return false;
  const manager = demoPersonas[managerId];
  const target = demoPersonas[targetPersonaId];
  const rec = getPersonnelRecord(targetPersonaId);
  if (rec.managerId !== managerId) return false;
  return isSamePersonnelRegion(manager, target);
}

function getNextRank(personaId) {
  const rec = getPersonnelRecord(personaId);
  const ladder = RANK_LADDERS[getAgencyLadderKey(rec.agencyCode)] || RANK_LADDERS.default;
  const idx = ladder.indexOf(rec.rank);
  return idx >= 0 && idx < ladder.length - 1 ? ladder[idx + 1] : null;
}

function syncPersonaFromPersonnel(personaId) {
  const rec = getPersonnelRecord(personaId);
  const p = demoPersonas[personaId];
  if (!p) return;
  if (rec.department) p.department = rec.department;
  if (rec.region) p.region = rec.region;
  if (rec.agencyName) p.group = rec.agencyName;
  if (rec.agencyCode) p.agency = rec.agencyCode;
  const shortPos = rec.position?.split(' ')[0] || p.role;
  p.role = `${shortPos} · ${rec.department?.split(' ')[0] || p.department}`;
  p.contourSub = `${rec.region} · ${rec.department} · ${rec.agencyName || p.group}`;
  updateHeaderContext();
  if (p.caseScope && typeof p.caseScope === 'object') {
    if (rec.region) p.caseScope.region = rec.region;
    if (rec.department) p.caseScope.department = rec.department;
    if (rec.agencyCode) p.caseScope.agency = rec.agencyCode;
  }
}

function applyHrRequest(req) {
  const rec = personnelState[req.personaId];
  const p = demoPersonas[req.personaId];
  if (!rec || !p) return;
  const today = '14.06.2028';
  if (req.type === 'promotion' && req.targetRank) {
    rec.rank = req.targetRank;
    rec.rankDate = today;
    rec.history.unshift({ date: today, kind: 'promotion', text: `Присвоено звание ${req.targetRank}` });
  }
  if (req.type === 'transfer_dept' && req.targetDept) {
    rec.history.unshift({ date: today, kind: 'transfer', text: `Перевод в ${req.targetDept}` });
    rec.department = req.targetDept;
    p.department = req.targetDept;
  }
  if (req.type === 'transfer_region' && req.targetRegion) {
    rec.history.unshift({ date: today, kind: 'transfer', text: `Перевод в ${req.targetRegion}` });
    rec.region = req.targetRegion;
    p.region = req.targetRegion;
  }
  if (req.type === 'transfer_agency' && req.targetAgency) {
    rec.history.unshift({ date: today, kind: 'transfer', text: `Перевод в ${req.targetAgency}` });
    rec.agencyName = req.targetAgency;
    p.group = req.targetAgency;
  }
  syncPersonaFromPersonnel(req.personaId);
  saveHrState();
  if (req.personaId === activePersonaId) applyDemoPersona();
}

function processHrAutomation() {
  let changed = false;
  hrRequests.forEach(req => {
    if (req.status === 'submitted' && req.autoManager) {
      req.status = 'manager_ok';
      req.log = [...(req.log || []), { at: '14.06.2028', text: 'Автосогласование: руководитель в отпуске, замещение' }];
      changed = true;
    }
    if (req.status === 'manager_ok') {
      req.status = 'hr_ok';
      req.log = [...(req.log || []), { at: '14.06.2028', text: 'Кадровый контур: проверка стажа и вакансий' }];
      changed = true;
    }
    if (req.status === 'hr_ok') {
      req.status = 'applied';
      req.log = [...(req.log || []), { at: '14.06.2028', text: 'Приказ сформирован · доступы пересчитаны' }];
      applyHrRequest(req);
      changed = true;
    }
  });
  if (changed) saveHrState();
}

function validateHrSubmission(type, payload, personaId) {
  const reason = (payload?.reason || '').trim();
  if (reason.length < 8) return 'Укажите основание не короче 8 символов (ПОЛ-009).';
  if (type === 'promotion') {
    const rec = getPersonnelRecord(personaId);
    if ((rec.disciplinary || []).some(d => d.kind === 'reprimand' && d.date >= '01.2028')) {
      return 'Повышение заблокировано: действует выговор.';
    }
  }
  if (type === 'transfer_agency' && !reason.includes('приказ') && !reason.includes('ходатайство') && !reason.includes('ПОЛ')) {
    return 'Перевод в другое ведомство требует ссылку на приказ или ходатайство кадрового органа.';
  }
  return null;
}

function submitHrRequest(type, payload) {
  const p = getActivePersona();
  const err = validateHrSubmission(type, payload, p.id);
  if (err) { showToast(err); return; }
  hrSeq += 1;
  const nextRank = type === 'promotion' ? getNextRank(p.id) : null;
  if (type === 'promotion' && !nextRank) {
    showToast('Достигнуто максимальное звание.');
    return;
  }
  const req = {
    id: `КЗ-${hrSeq}`,
    personaId: p.id,
    type,
    status: 'submitted',
    created: '14.06.2028',
    targetRank: nextRank,
    targetDept: payload?.dept,
    targetRegion: payload?.region,
    targetAgency: payload?.agency,
    reason: payload?.reason || '',
    log: [{ at: '14.06.2028', text: 'Проверка ПОЛ-009: основание принято' }],
    autoManager: false
  };
  hrRequests.unshift(req);
  saveHrState();
  closeHrRequestModal();
  profileTab = 'requests';
  renderProfile();
  showToast(`${req.id} подана · на согласовании у руководителя (ПОЛ-009)`);
}

function managerApproveHr(requestId, approved) {
  const req = hrRequests.find(r => r.id === requestId);
  const viewer = getActivePersona();
  if (!req) return;
  if (!canManagePersona(viewer.id, req.personaId)) {
    showToast('ПОЛ-009: нельзя согласовать заявку вне подчинения или за себя.');
    return;
  }
  if (req.personaId === viewer.id) {
    showToast('Запрещено согласовывать собственную заявку.');
    return;
  }
  req.status = approved ? 'manager_ok' : 'manager_no';
  req.log = [...(req.log || []), { at: '14.06.2028', text: approved ? `Согласовано: ${viewer.name}` : 'Отклонено руководителем' }];
  saveHrState();
  if (approved) {
    processHrAutomation();
    renderStaff();
  }
  renderProfile();
  showToast(approved ? 'Согласовано' : 'Отклонено');
}

function issueDiscipline(targetId, kind, text) {
  const viewer = getActivePersona();
  if (!canManagePersona(viewer.id, targetId)) {
    showToast('ПОЛ-009: взыскание только по линии подчинения.');
    return;
  }
  const rec = getPersonnelRecord(targetId);
  rec.disciplinary.unshift({ date: '06.2028', kind, issuer: viewer.name, text });
  saveHrState();
  closeDisciplineModal();
  renderStaff();
  showToast(`${DISCIPLINE_LABELS[kind]} внесено`);
}

function renderProfile() {
  const root = document.getElementById('profile-root');
  if (!root) return;
  const viewer = getActivePersona();
  const rec = getPersonnelRecord(viewer.id);
  const ctx = document.getElementById('profile-context');
  if (ctx) {
    ctx.textContent = profileTab === 'requests'
      ? 'Статус кадровых заявок · исполнение после согласования'
      : `${rec.rank} · ${rec.department || viewer.department} · заявки через ПОЛ-009`;
  }
  document.querySelectorAll('#view-profile .profile-tab').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.tab === profileTab);
  });
  if (profileTab === 'requests') {
    const myRequests = hrRequests.filter(r => r.personaId === viewer.id);
    root.innerHTML = renderOwnHrRequests(myRequests);
    return;
  }
  root.innerHTML = renderOwnProfileCard(rec);
}

function renderPersonnelAvatarCompact(rec) {
  return `<div class="profile-avatar-lg profile-avatar-photo profile-avatar-compact" aria-hidden="true">${escapeHtml(rec.avatar || '—')}</div>`;
}

function renderPersonnelFactsCompact(rec, pres) {
  const email = getCorporateEmail(rec.personaId);
  const manager = getPersonnelManagerName(rec.managerId);
  const optional = (label, val) => val ? `<div><dt>${label}</dt><dd>${escapeHtml(val)}</dd></div>` : '';
  return `<dl class="profile-facts profile-facts-compact">
    <div><dt>Дата звания</dt><dd>${escapeHtml(rec.rankDate || '—')}</dd></div>
    <div><dt>Ведомство</dt><dd>${escapeHtml(rec.agencyName || '—')}</dd></div>
    <div><dt>Отдел</dt><dd>${escapeHtml(rec.department || '—')}</dd></div>
    <div><dt>Регион</dt><dd>${escapeHtml(rec.region || '—')}</dd></div>
    <div><dt>Табельный №</dt><dd>${escapeHtml(rec.tabNumber || '—')}</dd></div>
    <div><dt>На службе с</dt><dd>${escapeHtml(rec.hireDate || '—')}</dd></div>
    <div><dt>Руководитель</dt><dd>${escapeHtml(manager)}</dd></div>
    <div><dt>Поощрения</dt><dd>${rec.merits ?? 0}</dd></div>
    <div><dt>Корп. почта</dt><dd class="profile-mail-cell">${corpMailLinkHtml(email)}</dd></div>
    <div><dt>ЕСИА</dt><dd><code class="mono-sm">${escapeHtml(pres?.cert || '—')}</code></dd></div>
    ${optional('Дата рождения', rec.birthDate)}
    ${optional('Телефон', rec.phone)}
    ${optional('Образование', rec.education)}
  </dl>`;
}

function renderOwnProfileHrActions(rec) {
  const canPromote = !!getNextRank(rec.personaId);
  const pending = hrRequests.filter(r => r.personaId === rec.personaId && !['applied', 'rejected', 'manager_no'].includes(r.status));
  return `
    <div class="profile-hr-actions">
      <div class="profile-hr-actions-head">
        <span class="profile-hr-actions-title">Кадровые заявки</span>
        <span class="profile-hr-badge">ПОЛ-009 · согласование</span>
      </div>
      <p class="muted profile-hr-hint">Не меняет звание и должность сразу. Маршрут: вы → руководитель → кадры ведомства.</p>
      <div class="profile-actions profile-actions-inline">
        <button type="button" class="btn-sm profile-hr-req-btn" onclick="openHrRequestModal('promotion')" ${canPromote ? '' : 'disabled'} title="Подать заявку на повышение звания">Заявка · повышение</button>
        <button type="button" class="btn-sm profile-hr-req-btn" onclick="openHrRequestModal('transfer_dept')" title="Подать заявку на перевод в другой отдел">Заявка · перевод в отдел</button>
        <button type="button" class="btn-sm profile-hr-req-btn" onclick="openHrRequestModal('transfer_region')" title="Подать заявку на перевод в другой регион">Заявка · перевод в регион</button>
      </div>
      ${pending.length ? `<p class="profile-hr-pending"><button type="button" class="case-link" onclick="setProfileTab('requests')">${pending.length} на согласовании</button></p>` : ''}
    </div>`;
}

function renderOwnProfileCard(rec) {
  const pres = getPresence(rec.personaId);
  return `
    <div class="profile-compact-layout">
      <div class="panel profile-compact-hero">
        <div class="profile-identity-head">
          ${renderPersonnelAvatarCompact(rec)}
          <div class="profile-identity-text">
            <h2>${escapeHtml(rec.name)}</h2>
            <p class="profile-rank">${escapeHtml(rec.rank)} · ${escapeHtml(rec.position || '—')}</p>
            ${renderPersonnelPresenceRow(pres)}
          </div>
        </div>
        ${renderOwnProfileHrActions(rec)}
      </div>
      <div class="panel profile-compact-facts">${renderPersonnelFactsCompact(rec, pres)}</div>
      <div class="profile-compact-bottom">
        <div class="panel"><h3>Движение по службе</h3><ul class="profile-history profile-history-compact">${renderPersonnelHistoryList(rec)}</ul></div>
        <div class="panel"><h3>Дисциплина</h3><ul class="profile-disc-list profile-disc-list-compact">${renderPersonnelDisciplineList(rec, false)}</ul></div>
      </div>
    </div>`;
}

function renderOwnHrRequests(requests) {
  if (!requests.length) {
    return `<div class="panel"><p class="muted">Нет заявок. На вкладке «Служебные данные» можно подать заявку на повышение или перевод — изменения вступят в силу только после согласования.</p></div>`;
  }
  return `<div class="panel panel-table">
    <p class="muted profile-hr-requests-note">Статус заявок · исполнение только после решения руководителя и кадров (ПОЛ-009)</p>
    <div class="table-scroll"><table class="data-table"><thead><tr><th>№</th><th>Тип заявки</th><th>Статус</th><th>Детали</th></tr></thead><tbody>
    ${requests.map(r => `<tr><td>${r.id}</td><td>${HR_REQUEST_TYPES[r.type]?.label}</td>
      <td><span class="status ${r.status === 'applied' ? 'fulfilled' : 'progress'}">${HR_STATUS_LABELS[r.status] || r.status}</span></td>
      <td class="muted">${escapeHtml(r.targetRank || r.targetDept || r.targetRegion || r.targetAgency || '—')}</td></tr>`).join('')}
  </tbody></table></div></div>`;
}

function setProfileTab(tab) { profileTab = tab; renderProfile(); }

const STAFF_TAB_META = {
  team: { id: 'team', label: 'Состав', icon: STAFF_USERS_ICON, color: '#3b82f6', desc: 'Подчинённые сотрудники' },
  hr: { id: 'hr', label: 'Согласования', icon: '☰', color: '#6366f1', desc: 'Заявки на перевод и звание' },
  structures: { id: 'structures', label: 'Структуры', icon: '▣', color: '#06b6d4', desc: 'Ведомства и контуры' },
  sessions: { id: 'sessions', label: 'Сессии', icon: '◎', color: '#10b981', desc: 'Активные подключения' },
  accounts: { id: 'accounts', label: 'Учётные записи', icon: '👤', color: '#3b82f6', desc: 'Заявки на УЗ и роли' }
};

function getVisibleStaffTabs(viewer) {
  const isTechAdmin = isTechAdminPersona(viewer);
  const isFuncAdmin = isFuncAdminPersona(viewer);
  const isAdminStaff = isTechAdmin || isFuncAdmin;
  const tabs = [];
  if (!isAdminStaff) {
    tabs.push('team', 'hr');
  }
  if (isTechAdmin) {
    tabs.push('structures', 'sessions');
  }
  if (isAdminStaff) {
    tabs.push('accounts');
  }
  return tabs;
}

function getStaffHeroMeta(viewer, tab) {
  const isTechAdmin = isTechAdminPersona(viewer);
  const isFuncAdmin = isFuncAdminPersona(viewer);
  if (isTechAdmin) {
    const titles = {
      structures: 'Структуры ведомств',
      sessions: 'Активные сессии',
      accounts: 'Учётные записи'
    };
    return {
      title: titles[tab] || 'Кадровый контур ЦОД',
      subtitle: 'ПОЛ-008 · тех. данные подключений · без содержимого дел',
      policy: 'ПОЛ-009'
    };
  }
  if (isFuncAdmin) {
    return {
      title: tab === 'accounts' ? 'Учётные записи ведомства' : 'Персонал ведомства',
      subtitle: `${viewer.adminAgencyScope || viewer.group} · ПОЛ-008 · без доступа к делам`,
      policy: 'ПОЛ-009'
    };
  }
  return {
    title: tab === 'hr' ? 'Согласования' : 'Состав отдела',
    subtitle: `${viewer.region || viewer.department || viewer.group} · подчинение только в пределах региона`,
    policy: 'ПОЛ-009'
  };
}

function getStaffKpis(viewer, tab) {
  const kpis = [];
  if (tab === 'structures' && isTechAdminPersona(viewer)) {
    const groups = getStructuresAgencyGroups();
    const ids = groups.flatMap(g => g.ids);
    const online = ids.filter(id => getPresence(id).online).length;
    kpis.push({ val: groups.length, label: 'ведомств' });
    kpis.push({ val: online, label: 'в сети', accent: 'success' });
    kpis.push({ val: ids.length, label: 'сотрудников' });
  } else if (tab === 'sessions' && isTechAdminPersona(viewer)) {
    const sessions = getAllActiveSessions();
    const vpn = sessions.filter(s => s.vpn && s.vpn !== 'нет' && !s.vpn.startsWith('нет')).length;
    kpis.push({ val: sessions.length, label: 'сессий', accent: 'success' });
    kpis.push({ val: vpn, label: 'через VPN' });
    kpis.push({ val: new Set(sessions.map(s => s.agency)).size, label: 'ведомств' });
  } else if (tab === 'accounts' && (isTechAdminPersona(viewer) || isFuncAdminPersona(viewer))) {
    const pending = userAccountRequests.filter(r => r.status === 'pending' || r.status === 'security_check').length;
    const active = userAccountRequests.filter(r => r.status === 'active').length;
    kpis.push({ val: pending, label: 'в очереди', accent: pending ? 'warn' : null });
    kpis.push({ val: active, label: 'активных', accent: 'success' });
    kpis.push({ val: userAccountRequests.length, label: 'всего' });
  } else if (tab === 'hr') {
    const pending = hrRequests.filter(r => r.status === 'submitted' && canManagePersona(viewer.id, r.personaId)).length;
    kpis.push({ val: pending, label: 'на согласовании', accent: pending ? 'warn' : null });
    kpis.push({ val: getSubordinates(viewer.id).length, label: 'подчинённых' });
  } else {
    kpis.push({ val: getSubordinates(viewer.id).length, label: 'в составе' });
    const online = getSubordinates(viewer.id).filter(s => getPresence(s.personaId).online).length;
    kpis.push({ val: online, label: 'в сети', accent: 'success' });
  }
  return kpis;
}

function renderStaffHero(viewer, tab) {
  const meta = getStaffHeroMeta(viewer, tab);
  const kpis = getStaffKpis(viewer, tab);
  const hero = document.getElementById('staff-hero');
  if (!hero) return;
  hero.innerHTML = `
    <div class="staff-hero-main">
      <h2 class="staff-hero-title">${escapeHtml(meta.title)}</h2>
      <p class="staff-hero-sub muted">${escapeHtml(meta.subtitle)}</p>
    </div>
    <div class="staff-kpi-strip">
      ${kpis.map(k => `<div class="staff-kpi${k.accent ? ` staff-kpi-${k.accent}` : ''}">
        <span class="staff-kpi-val">${k.val}</span>
        <span class="staff-kpi-label">${escapeHtml(k.label)}</span>
      </div>`).join('')}
    </div>`;
}

function renderStaffModuleNav(viewer) {
  const nav = document.getElementById('staff-module-nav');
  if (!nav) return;
  const tabs = getVisibleStaffTabs(viewer);
  if (!tabs.includes(staffTab)) staffTab = tabs[0] || 'team';
  if (tabs.length <= 1) {
    nav.innerHTML = '';
    nav.classList.add('hidden');
    return;
  }
  nav.classList.remove('hidden');
  nav.innerHTML = tabs.map(id => {
    const m = STAFF_TAB_META[id];
    const badge = id === 'hr'
      ? hrRequests.filter(r => r.status === 'submitted' && canManagePersona(viewer.id, r.personaId)).length
      : id === 'accounts'
        ? userAccountRequests.filter(r => r.status === 'pending' || r.status === 'security_check').length
        : 0;
    return `<button type="button" class="staff-module-btn ${staffTab === id ? 'active' : ''}"
      style="--staff-color:${m.color}"
      data-staff-tab="${id}" onclick="setStaffTab('${id}')" role="tab" aria-selected="${staffTab === id}">
      <span class="staff-module-icon">${m.icon}</span>
      <span class="staff-module-text">
        <span class="staff-module-name">${escapeHtml(m.label)}</span>
        <span class="staff-module-desc">${escapeHtml(m.desc)}</span>
      </span>
      ${badge ? `<span class="staff-module-badge">${badge}</span>` : ''}
    </button>`;
  }).join('');
}

function renderStaff() {
  const root = document.getElementById('staff-root');
  if (!root) return;
  const viewer = getActivePersona();
  const isTechAdmin = isTechAdminPersona(viewer);
  const isFuncAdmin = isFuncAdminPersona(viewer);
  const isAdminStaff = isTechAdmin || isFuncAdmin;

  renderStaffModuleNav(viewer);
  renderStaffHero(viewer, staffTab);

  const layout = document.querySelector('.staff-layout');
  if (layout) layout.classList.toggle('staff-layout-single', getVisibleStaffTabs(viewer).length <= 1);

  if (staffTab === 'accounts' && isAdminStaff) {
    root.innerHTML = `<div class="staff-panel-wrap">${renderUserAccountsPanel()}</div>`;
    return;
  }
  if (staffTab === 'structures' && isTechAdmin) {
    root.innerHTML = `<div class="staff-panel-wrap staff-panel-structures">${renderStaffStructuresPanel()}</div>`;
    return;
  }
  if (staffTab === 'sessions' && isTechAdmin) {
    root.innerHTML = `<div class="staff-panel-wrap">${renderStaffSessionsPanel()}</div>`;
    return;
  }
  if (staffTab === 'hr') {
    root.innerHTML = `<div class="staff-panel-wrap">${renderStaffHrPanel(viewer)}</div>`;
    return;
  }
  root.innerHTML = `<div class="staff-panel-wrap">${renderStaffTeamPanel(viewer)}</div>`;
}

function setStaffTab(tab) { staffTab = tab; renderStaff(); }

function renderStaffTeamPanel(viewer) {
  const subs = getSubordinates(viewer.id);
  if (!subs.length && !isAnyAdminPersona(viewer)) {
    return `<div class="panel"><p class="muted">Нет подчинённых в вашем регионе (${escapeHtml(viewer.region || '—')}). Линия подчинения действует только в пределах одного региона (ПОЛ-009).</p></div>`;
  }
  const list = subs;
  const selected = staffSelectedId && list.some(s => s.personaId === staffSelectedId) ? staffSelectedId : list[0]?.personaId;
  staffSelectedId = selected;
  const nav = list.map(s => {
    const pres = getPresence(s.personaId);
    return `
    <button type="button" class="agencies-nav-item staff-team-nav-item ${selected === s.personaId ? 'active' : ''}" onclick="selectStaffMember('${s.personaId}')">
      ${presenceDotHtml(pres.online)}
      <span class="agencies-nav-text">
        <span class="agencies-nav-name">${escapeHtml(s.name)}</span>
        <span class="agencies-nav-tag">${pres.online ? 'в сети' : 'не в сети'}</span>
      </span>
    </button>`;
  }).join('');
  const rec = getPersonnelRecord(selected);
  const canManage = canManagePersona(viewer.id, selected);
  const detail = renderStaffMemberDetail(rec, canManage, false);
  return `<div class="staff-team-layout"><nav class="staff-team-nav">${nav}</nav><div class="staff-team-detail">${detail}</div></div>`;
}

function selectStaffMember(id) { staffSelectedId = id; renderStaff(); }

function renderStaffMemberDetail(rec, canManage, fullPresence = false) {
  const pres = getPresence(rec.personaId);
  const actions = canManage ? `<div class="profile-actions profile-actions-inline staff-dossier-actions">
    <button class="btn-sm" onclick="openDisciplineModal('${rec.personaId}','remark')">Замечание</button>
    <button class="btn-sm btn-warn" onclick="openDisciplineModal('${rec.personaId}','reprimand')">Выговор</button>
    <button class="btn-sm" onclick="openDisciplineModal('${rec.personaId}','encouragement')">Поощрение</button>
  </div>` : '';
  return `<div class="profile-compact-layout staff-dossier-compact">
    <div class="panel profile-compact-hero">
      <div class="profile-identity-head">
        ${renderPersonnelAvatarCompact(rec)}
        <div class="profile-identity-text">
          <h2>${escapeHtml(rec.name)}</h2>
          <p class="profile-rank">${escapeHtml(rec.rank)} · ${escapeHtml(rec.position || '—')}</p>
          ${renderPersonnelPresenceRow(pres, fullPresence)}
        </div>
      </div>
      ${actions}
    </div>
    <div class="panel profile-compact-facts">${renderPersonnelFactsCompact(rec, pres)}</div>
    <div class="profile-compact-bottom">
      <div class="panel staff-dossier-panel"><h3>Движение по службе</h3><ul class="profile-history profile-history-compact">${renderPersonnelHistoryList(rec)}</ul></div>
      <div class="panel staff-dossier-panel"><h3>Дисциплина</h3><ul class="profile-disc-list profile-disc-list-compact">${renderPersonnelDisciplineList(rec, false)}</ul></div>
      <div class="panel staff-dossier-panel staff-dossier-presence"><h3>Присутствие</h3>${renderPersonnelPresenceRow(pres, true)}</div>
    </div>
  </div>`;
}

function renderStaffStructuresPanel() {
  return renderStructuresPanel();
}

function renderStaffSessionsPanel() {
  tablePageRefresh['staff-sessions'] = () => {
    if (document.getElementById('view-staff')?.classList.contains('active')) renderStaff();
  };
  const sessions = getAllActiveSessions();
  const meta = paginateList(sessions, 'staff-sessions');
  const tableRows = meta.slice.length
    ? meta.slice.map(s => `<tr>
        <td><code class="mono-sm">${escapeHtml(s.sessionId)}</code></td>
        <td><strong>${escapeHtml(s.name)}</strong><br><span class="muted">${escapeHtml(s.login)}</span></td>
        <td>${escapeHtml(s.agency)}</td>
        <td><span class="structure-tag-sm">${escapeHtml(s.contour)}</span></td>
        <td>${escapeHtml(s.client || '—')}<br><span class="muted mono-sm">${escapeHtml(s.ip || '—')}</span></td>
        <td class="muted">${escapeHtml(s.region)}</td>
        <td>${s.vpn && s.vpn !== 'нет' && !s.vpn.startsWith('нет') ? '<span class="structure-vpn-tag">VPN</span>' : '<span class="muted">—</span>'}</td>
        <td class="muted">${escapeHtml(s.userAgent || '—')}</td>
      </tr>`).join('')
    : '<tr><td colspan="8" class="muted staff-empty-cell">Нет активных сессий</td></tr>';
  return `<div class="panel staff-sessions-panel">
    <div class="staff-panel-head">
      <h3>Активные подключения</h3>
      <button type="button" class="btn-sm" onclick="adminRefreshSessions(); setStaffTab('sessions')">↻ Обновить</button>
    </div>
    <div class="paginated-table-body">
      <div class="table-scroll table-scroll-paged"><table class="data-table staff-sessions-table"><thead><tr>
        <th>Сессия</th><th>Пользователь</th><th>Ведомство</th><th>Контур</th><th>АРМ / IP</th><th>Регион</th><th>VPN</th><th>Клиент</th>
      </tr></thead><tbody>
        ${tableRows}
      </tbody></table></div>
      ${renderTablePagination(meta)}
    </div>
  </div>`;
}

function renderStaffHrPanel(viewer) {
  const pending = hrRequests.filter(r => r.status === 'submitted' && canManagePersona(viewer.id, r.personaId));
  if (!pending.length) return '<div class="panel"><p class="muted">Нет заявок на согласовании.</p></div>';
  return `<div class="panel panel-table"><div class="table-scroll"><table class="data-table"><thead><tr><th>№</th><th>Сотрудник</th><th>Тип</th><th>Детали</th><th>Основание</th><th></th></tr></thead><tbody>
    ${pending.map(r => { const s = getPersonnelRecord(r.personaId); return `<tr>
      <td>${r.id}</td><td>${escapeHtml(s.name)}</td><td>${HR_REQUEST_TYPES[r.type]?.label}</td>
      <td>${escapeHtml(r.targetRank || r.targetDept || r.targetRegion || r.targetAgency || '—')}</td>
      <td class="muted">${escapeHtml(r.reason)}</td>
      <td><button class="btn-xs approve" onclick="managerApproveHr('${r.id}',true)">Да</button> <button class="btn-xs reject" onclick="managerApproveHr('${r.id}',false)">Нет</button></td>
    </tr>`; }).join('')}
  </tbody></table></div>
  <p class="muted" style="margin-top:0.75rem;font-size:0.8rem">ПОЛ-009: согласование только по линии подчинения. Собственные заявки заблокированы.</p></div>`;
}

const USER_ACCOUNT_STATUS = {
  pending: 'На проверке',
  security_ok: 'Проверка пройдена',
  security_fail: 'Отклонено',
  active: 'Учётная запись создана'
};

function renderUserAccountsPanel() {
  tablePageRefresh['ua-queue'] = () => renderAdminModuleDetail('USR');
  const meta = paginateList(userAccountRequests, 'ua-queue');
  const rowsHtml = !userAccountRequests.length
    ? '<tr><td colspan="4" class="muted">Пусто</td></tr>'
    : meta.slice.map(r => `<tr><td>${r.id}</td><td>${escapeHtml(r.name)}${r.rank ? `<br><span class="muted">${escapeHtml(r.rank)}</span>` : ''}</td><td><span class="status ${r.status === 'active' ? 'fulfilled' : r.status === 'security_fail' ? 'draft' : 'progress'}">${USER_ACCOUNT_STATUS[r.status]}</span></td><td class="muted">${escapeHtml(r.checks || '—')}</td></tr>`).join('');
  return `<div class="staff-accounts-grid">
    <div class="panel staff-accounts-form">
      <div class="staff-panel-head"><h3>Новая учётная запись</h3></div>
      <p class="muted staff-panel-hint">Заявка → проверка ИБ → ЕСИА → назначение ролей (ПОЛ-009)</p>
      <label class="field"><span>ФИО</span><input type="text" id="ua-name" placeholder="Фамилия И.О."></label>
      <label class="field"><span>Звание</span><select id="ua-rank">${userAccountRankOptionsHtml('МВД России')}</select></label>
      <label class="field"><span>Должность</span><input type="text" id="ua-role" placeholder="Следователь · СО №3"></label>
      <label class="field"><span>Ведомство</span><select id="ua-agency" onchange="updateUserAccountRankOptions()"><option>МВД России</option><option>СК России</option><option>ФСБ России</option></select></label>
      <label class="field"><span>Руководитель-инициатор</span><input type="text" id="ua-manager" value="Морозова Е.А."></label>
      <label class="field staff-accounts-basis-field"><span>Основание (приказ / штатное расписание)</span><textarea id="ua-basis" rows="2" placeholder="Приказ №… о вводе должности"></textarea></label>
      <div class="staff-accounts-form-actions">
        <button type="button" class="btn-primary" onclick="submitUserAccountRequest()">Подать заявку</button>
      </div>
    </div>
    <div class="panel staff-accounts-queue">
      <div class="staff-panel-head"><h3>Очередь заявок</h3></div>
      <div class="paginated-table-body">
        <div class="table-scroll table-scroll-paged"><table class="data-table"><thead><tr><th>№</th><th>ФИО</th><th>Статус</th><th>Проверки</th></tr></thead><tbody id="ua-queue-body">
          ${rowsHtml}
        </tbody></table></div>
        ${renderTablePagination(meta)}
      </div>
    </div>
  </div>`;
}

function submitUserAccountRequest() {
  const name = document.getElementById('ua-name')?.value.trim();
  const rank = document.getElementById('ua-rank')?.value;
  const role = document.getElementById('ua-role')?.value.trim();
  const agency = document.getElementById('ua-agency')?.value;
  const manager = document.getElementById('ua-manager')?.value.trim();
  const basis = document.getElementById('ua-basis')?.value.trim();
  if (!name || !rank || !role || basis.length < 12) { showToast('Заполните ФИО, звание, должность и основание (от 12 символов).'); return; }
  if (manager === name) { showToast('ПОЛ-009: инициатор не может совпадать с создаваемой учётной записью.'); return; }
  userAccountSeq += 1;
  const req = { id: `УЗ-${userAccountSeq}`, name, rank, role, agency, manager, basis, status: 'pending', checks: 'Ожидает' };
  userAccountRequests.unshift(req);
  saveHrState();
  resetTablePage('ua-queue');
  setTimeout(() => runUserAccountSecurityCheck(req.id), 1500);
  renderStaff();
  showToast(`${req.id} принята в обработку`);
}

function runUserAccountSecurityCheck(reqId) {
  const req = userAccountRequests.find(r => r.id === reqId);
  if (!req) return;
  const flags = [];
  if (req.basis.toLowerCase().includes('тест') && !req.basis.includes('приказ')) flags.push('слабое основание');
  if (req.name === req.manager) flags.push('конфликт ролей');
  if (/тех\.\s*админ|управление\s*ит/i.test(req.role) && !req.basis.includes('ПОЛ')) flags.push('эскалация привилегий');
  if (flags.length) {
    req.status = 'security_fail';
    req.checks = flags.join(', ');
  } else {
    req.status = 'security_ok';
    req.checks = 'ЕСИА, дубль, штатное расписание, ПОЛ-009';
    setTimeout(() => {
      req.status = 'active';
      req.checks = 'Учётная запись создана · роли назначены';
      saveHrState();
      renderStaff();
      showToast(`${reqId}: учётная запись активирована`);
    }, 2000);
  }
  saveHrState();
  renderStaff();
}

function canEditSuspects() {
  const rt = getActivePersona().roleType;
  return rt === 'inv' || rt === 'inv_lead' || rt === 'ops';
}

function getSuspectFullName(s) {
  return `${s.lastName || ''} ${s.firstName || ''} ${s.patronymic || ''}`.trim();
}

function inferSuspectRegionFromDossier(s) {
  if (!s) return null;
  const hay = `${s.address || ''} ${s.birthPlace || ''}`.toLowerCase();
  const regions = [...new Set(casesRegistry.map(c => c.region))].sort((a, b) => b.length - a.length);
  for (const r of regions) {
    if (hay.includes(r.toLowerCase())) return r;
  }
  if (hay.includes('москва')) return 'Москва';
  if (hay.includes('казан') || hay.includes('татарстан')) return 'Республика Татарстан';
  return null;
}

function getSuspectCaseMeta(caseId, suspect) {
  const c = getCaseById(caseId);
  if (c) return { region: c.region, department: c.department, agency: c.agencyName, crimeType: c.crimeType };
  const s = suspect || suspectDossiers.find(x => x.caseId === caseId);
  const region = inferSuspectRegionFromDossier(s) || '—';
  return { region, department: '—', agency: '—', crimeType: '—' };
}

function canEditSuspectDossier(s) {
  return canEditSuspects() && personaCanAccessCase(s.caseId);
}

function getSuspectRegionOptions() {
  return [...new Set(
    suspectDossiers.map(s => getSuspectCaseMeta(s.caseId, s).region).filter(r => r && r !== '—')
  )].sort();
}

function suspectFiltersActive() {
  return !!(suspectSearchQuery.trim() || suspectFilterRegion || suspectFilterStatus);
}

function filterSuspectDossiers(list) {
  const q = suspectSearchQuery.trim().toLowerCase();
  return list.filter(s => {
    const meta = getSuspectCaseMeta(s.caseId, s);
    if (suspectFilterRegion && meta.region !== suspectFilterRegion) return false;
    if (suspectFilterStatus && s.status !== suspectFilterStatus) return false;
    if (!q) return true;
    const hay = [
      getSuspectFullName(s), s.lastName, s.firstName, s.patronymic,
      s.phones, s.emails, s.caseId, s.address, s.birthPlace, s.passport, s.inn,
      meta.region, meta.department, meta.agency, meta.crimeType, s.status
    ].join(' ').toLowerCase();
    return hay.includes(q);
  });
}

function getVisibleSuspects() {
  return filterSuspectDossiers(suspectDossiers.slice()).sort((a, b) => {
    const aIn = personaCanAccessCase(a.caseId) ? 0 : 1;
    const bIn = personaCanAccessCase(b.caseId) ? 0 : 1;
    if (aIn !== bIn) return aIn - bIn;
    return (a.lastName || '').localeCompare(b.lastName || '', 'ru');
  });
}

function prepareSuspectsView() {
  ensureSuspectDossiers();
  if (suspectDossiers.length && suspectFiltersActive() && !filterSuspectDossiers(suspectDossiers.slice()).length) {
    suspectSearchQuery = '';
    suspectFilterRegion = '';
    suspectFilterStatus = '';
  }
}

function suspectAvatar(s) {
  return `${(s.lastName || '?')[0]}${(s.firstName || '')[0]}`.toUpperCase();
}

function renderSuspectsToolbar(total, filtered) {
  const wrap = document.getElementById('suspects-toolbar-wrap');
  if (!wrap) return;
  const regions = getSuspectRegionOptions();
  const inScope = suspectDossiers.filter(s => personaCanAccessCase(s.caseId)).length;
  const filtersOn = suspectFiltersActive();
  const subText = filtersOn
    ? `${filtered} из ${total} · ${inScope} в вашем охвате · остальные — только просмотр`
    : `${total} фигурантов · полный список · ${inScope} в вашем охвате · фильтры ниже необязательны`;
  wrap.innerHTML = `
    <div class="suspects-toolbar panel">
      <div class="suspects-toolbar-head">
        <div>
          <h2 class="suspects-toolbar-title">Дела фигурантов</h2>
          <p class="suspects-toolbar-sub muted">${subText}</p>
        </div>
        <button type="button" class="btn-sm suspects-reset-btn" onclick="resetSuspectFilters()">Сбросить</button>
      </div>
      <div class="suspects-filters">
        <label class="suspects-filter-field suspects-filter-search">
          <span>Поиск</span>
          <input type="search" id="suspect-search" placeholder="ФИО, телефон, дело, регион…" value="${escapeHtml(suspectSearchQuery)}"
            oninput="setSuspectSearch(this.value)">
        </label>
        <label class="suspects-filter-field">
          <span>Регион</span>
          <select id="suspect-filter-region" onchange="setSuspectFilterRegion(this.value)">
            <option value="">Все регионы</option>
            ${regions.map(r => `<option value="${escapeHtml(r)}"${suspectFilterRegion === r ? ' selected' : ''}>${escapeHtml(r)}</option>`).join('')}
          </select>
        </label>
        <label class="suspects-filter-field">
          <span>Статус</span>
          <select id="suspect-filter-status" onchange="setSuspectFilterStatus(this.value)">
            <option value="">Все статусы</option>
            <option value="подозреваемый"${suspectFilterStatus === 'подозреваемый' ? ' selected' : ''}>подозреваемый</option>
            <option value="обвиняемый"${suspectFilterStatus === 'обвиняемый' ? ' selected' : ''}>обвиняемый</option>
            <option value="потерпевший"${suspectFilterStatus === 'потерпевший' ? ' selected' : ''}>потерпевший</option>
            <option value="свидетель"${suspectFilterStatus === 'свидетель' ? ' selected' : ''}>свидетель</option>
          </select>
        </label>
      </div>
    </div>`;
}

function setSuspectSearch(val) {
  suspectSearchQuery = val;
  renderSuspects();
}

function setSuspectFilterRegion(val) {
  suspectFilterRegion = val;
  renderSuspects();
}

function setSuspectFilterStatus(val) {
  suspectFilterStatus = val;
  renderSuspects();
}

function resetSuspectFilters() {
  suspectSearchQuery = '';
  suspectFilterRegion = '';
  suspectFilterStatus = '';
  renderSuspects();
}

function renderSuspects() {
  ensureSuspectDossiers();
  const nav = document.getElementById('suspects-nav');
  const detail = document.getElementById('suspects-detail');
  if (!nav || !detail) return;
  const total = suspectDossiers.length;
  const list = getVisibleSuspects();
  renderSuspectsToolbar(total, list.length);

  if (!total) {
    nav.innerHTML = '';
    detail.innerHTML = '<div class="panel suspects-empty"><p class="muted">Нет личных дел фигурантов в демо-контуре.</p></div>';
    return;
  }
  if (!list.length) {
    nav.innerHTML = '<p class="suspects-nav-empty-hint muted">Нет совпадений</p>';
    detail.innerHTML = `<div class="panel suspects-empty suspects-empty-panel">
      <p class="muted">Нет фигурантов по заданным фильтрам.</p>
      <button type="button" class="btn-sm" onclick="resetSuspectFilters()">Сбросить фильтры</button>
    </div>`;
    return;
  }
  if (!list.some(s => s.id === activeSuspectId)) activeSuspectId = list[0].id;

  const searchHadFocus = document.activeElement?.id === 'suspect-search';
  const searchPos = searchHadFocus ? document.activeElement.selectionStart : null;

  nav.innerHTML = list.map(s => {
    const meta = getSuspectCaseMeta(s.caseId, s);
    const outOfScope = !personaCanAccessCase(s.caseId);
    return `
    <button type="button" class="agencies-nav-item suspects-nav-item ${s.id === activeSuspectId ? 'active' : ''}" onclick="selectSuspect('${s.id}')">
      <span class="suspect-nav-photo">${escapeHtml(suspectAvatar(s))}</span>
      <span class="agencies-nav-text">
        <span class="agencies-nav-name">${escapeHtml(s.lastName)} ${escapeHtml(s.firstName[0])}.</span>
        <span class="agencies-nav-tag">${escapeHtml(s.status)} · ${escapeHtml(meta.region)}</span>
        ${outOfScope ? '<span class="suspects-nav-ro">только просмотр</span>' : ''}
      </span>
    </button>`;
  }).join('');

  detail.innerHTML = renderSuspectForm(list.find(s => s.id === activeSuspectId));

  if (searchHadFocus) {
    const el = document.getElementById('suspect-search');
    if (el) {
      el.focus();
      if (searchPos != null) el.setSelectionRange(searchPos, searchPos);
    }
  }
}

function selectSuspect(id) { activeSuspectId = id; renderSuspects(); }

function renderSuspectForm(s) {
  if (!s) return '';
  const editable = canEditSuspectDossier(s);
  const ro = editable ? '' : 'readonly';
  const dis = editable ? '' : 'disabled';
  const meta = getSuspectCaseMeta(s.caseId, s);
  const outOfScope = !personaCanAccessCase(s.caseId);
  return `<div class="panel suspect-form-panel suspect-form-compact">
    <div class="suspect-form-head">
      <div class="suspect-photo-lg">${escapeHtml(suspectAvatar(s))}</div>
      <div class="suspect-form-head-text">
        <h2>${escapeHtml(getSuspectFullName(s))}</h2>
        <span class="badge investigating">${escapeHtml(s.status)}</span>
        ${outOfScope ? '<span class="suspects-ro-badge">Только просмотр</span>' : ''}
      </div>
    </div>
    <dl class="suspect-case-facts">
      <div><dt>Дело</dt><dd><button type="button" class="case-link" onclick="openCase('${s.caseId}')">${escapeHtml(s.caseId)}</button></dd></div>
      <div><dt>Регион</dt><dd>${escapeHtml(meta.region)}</dd></div>
      <div><dt>Отдел</dt><dd>${escapeHtml(meta.department)}</dd></div>
      <div><dt>Состав</dt><dd>${escapeHtml(meta.crimeType)}</dd></div>
    </dl>
    <form class="suspect-form" onsubmit="saveSuspectDossier(event)">
      <input type="hidden" id="sus-id" value="${s.id}">
      <div class="suspect-form-grid suspect-form-grid-compact">
        <label class="field"><span>Фамилия</span><input type="text" id="sus-ln" value="${escapeHtml(s.lastName)}" ${ro} required></label>
        <label class="field"><span>Имя</span><input type="text" id="sus-fn" value="${escapeHtml(s.firstName)}" ${ro} required></label>
        <label class="field"><span>Отчество</span><input type="text" id="sus-pn" value="${escapeHtml(s.patronymic)}" ${ro}></label>
        <label class="field"><span>Статус</span><select id="sus-status" ${dis}><option ${s.status === 'подозреваемый' ? 'selected' : ''}>подозреваемый</option><option ${s.status === 'обвиняемый' ? 'selected' : ''}>обвиняемый</option><option ${s.status === 'потерпевший' ? 'selected' : ''}>потерпевший</option><option ${s.status === 'свидетель' ? 'selected' : ''}>свидетель</option></select></label>
        <label class="field"><span>Дата рожд.</span><input type="text" id="sus-birth" value="${escapeHtml(s.birthDate)}" ${ro}></label>
        <label class="field"><span>Место рожд.</span><input type="text" id="sus-bplace" value="${escapeHtml(s.birthPlace)}" ${ro}></label>
        <label class="field"><span>Паспорт</span><input type="text" id="sus-pass" value="${escapeHtml(s.passport)}" ${ro}></label>
        <label class="field"><span>ИНН</span><input type="text" id="sus-inn" value="${escapeHtml(s.inn)}" ${ro}></label>
        <label class="field"><span>Телефон</span><input type="text" id="sus-phone" value="${escapeHtml(s.phones)}" ${ro}></label>
        <label class="field"><span>Почта</span><input type="text" id="sus-email" value="${escapeHtml(s.emails)}" ${ro}></label>
        <label class="field suspect-span-2"><span>Адрес</span><input type="text" id="sus-addr" value="${escapeHtml(s.address)}" ${ro}></label>
        <label class="field suspect-span-2"><span>Меры принуждения</span><input type="text" id="sus-measures" value="${escapeHtml(s.measures)}" ${ro}></label>
        <label class="field suspect-span-2"><span>Примечание</span><textarea id="sus-notes" rows="2" ${ro}>${escapeHtml(s.notes)}</textarea></label>
      </div>
      ${editable ? '<button type="submit" class="btn-primary btn-sm">Сохранить</button>' : `<p class="muted suspect-ro-hint">${outOfScope ? 'Редактирование недоступно · вы не в составе дела' : 'Только просмотр (надзорный контур)'}</p>`}
      <p class="muted suspect-meta">Изменено ${escapeHtml(s.updatedAt)} · ${escapeHtml(s.updatedBy)}</p>
    </form></div>`;
}

function saveSuspectDossier(e) {
  e.preventDefault();
  const id = document.getElementById('sus-id').value;
  const s = suspectDossiers.find(x => x.id === id);
  if (!s || !canEditSuspectDossier(s)) {
    showToast('Редактирование недоступно для этого дела.');
    return;
  }
  Object.assign(s, {
    lastName: document.getElementById('sus-ln').value.trim(),
    firstName: document.getElementById('sus-fn').value.trim(),
    patronymic: document.getElementById('sus-pn').value.trim(),
    status: document.getElementById('sus-status').value,
    birthDate: document.getElementById('sus-birth').value.trim(),
    birthPlace: document.getElementById('sus-bplace').value.trim(),
    passport: document.getElementById('sus-pass').value.trim(),
    inn: document.getElementById('sus-inn').value.trim(),
    address: document.getElementById('sus-addr').value.trim(),
    phones: document.getElementById('sus-phone').value.trim(),
    emails: document.getElementById('sus-email').value.trim(),
    measures: document.getElementById('sus-measures').value.trim(),
    notes: document.getElementById('sus-notes').value.trim(),
    updatedAt: '14.06.2028',
    updatedBy: getActivePersona().name
  });
  saveHrState();
  showToast('Личное дело фигуранта сохранено · запись в журнале аудита');
}

function openMyProfile() {
  profileTab = 'card';
  showView('profile');
  const view = document.getElementById('view-profile');
  if (view) view.scrollTop = 0;
}

window.openMyProfile = openMyProfile;

function openHrRequestModal(type) {
  const modal = document.getElementById('hr-request-modal');
  const typeSel = document.getElementById('hr-req-type');
  const titleEl = document.getElementById('hr-request-modal-title');
  if (!modal || !typeSel) return;
  typeSel.value = type;
  if (titleEl) titleEl.textContent = HR_REQUEST_TYPES[type]?.label || 'Кадровая заявка';
  updateHrRequestFields();
  modal.classList.remove('hidden');
}

function updateHrRequestFields() {
  const type = document.getElementById('hr-req-type')?.value;
  const fields = document.getElementById('hr-req-fields');
  const titleEl = document.getElementById('hr-request-modal-title');
  if (titleEl && type) titleEl.textContent = HR_REQUEST_TYPES[type]?.label || 'Кадровая заявка';
  if (!fields) return;
  if (type === 'transfer_dept') {
    fields.innerHTML = `<label class="field"><span>Целевой отдел</span><select id="hr-req-dept">${TRANSFER_DEPTS_MVD.map(d => `<option>${d}</option>`).join('')}</select></label>
      <label class="field"><span>Основание</span><input type="text" id="hr-req-reason" value="Производственная необходимость"></label>`;
  } else if (type === 'transfer_region') {
    fields.innerHTML = `<label class="field"><span>Целевой регион</span><select id="hr-req-region">${TRANSFER_REGIONS.map(r => `<option>${r}</option>`).join('')}</select></label>
      <label class="field"><span>Основание</span><input type="text" id="hr-req-reason" value="Перемещение по службе"></label>`;
  } else if (type === 'transfer_agency') {
    fields.innerHTML = `<label class="field"><span>Целевое ведомство</span><select id="hr-req-agency">${TRANSFER_AGENCIES.map(a => `<option>${a}</option>`).join('')}</select></label>
      <label class="field"><span>Основание</span><input type="text" id="hr-req-reason" value="Согласование кадрового органа"></label>`;
  } else if (type === 'promotion') {
    const next = getNextRank(getActivePersona().id);
    fields.innerHTML = `<p class="muted">Целевое звание: <strong>${next || '—'}</strong></p>
      <label class="field"><span>Основание</span><input type="text" id="hr-req-reason" value="Стаж и результаты службы"></label>`;
  }
}

function closeHrRequestModal() {
  document.getElementById('hr-request-modal')?.classList.add('hidden');
}

function confirmHrRequest() {
  const type = document.getElementById('hr-req-type')?.value;
  const reason = document.getElementById('hr-req-reason')?.value?.trim() || '';
  submitHrRequest(type, {
    dept: document.getElementById('hr-req-dept')?.value,
    region: document.getElementById('hr-req-region')?.value,
    agency: document.getElementById('hr-req-agency')?.value,
    reason
  });
}

let disciplineTargetId = null;

function openDisciplineModal(targetId, kind) {
  disciplineTargetId = targetId;
  const modal = document.getElementById('discipline-modal');
  const title = document.getElementById('discipline-modal-title');
  if (title) title.textContent = DISCIPLINE_LABELS[kind] || 'Взыскание';
  document.getElementById('discipline-kind').value = kind;
  document.getElementById('discipline-text').value = '';
  modal?.classList.remove('hidden');
}

function closeDisciplineModal() {
  document.getElementById('discipline-modal')?.classList.add('hidden');
  disciplineTargetId = null;
}

function confirmDiscipline() {
  if (!disciplineTargetId) return;
  const kind = document.getElementById('discipline-kind').value;
  const text = document.getElementById('discipline-text').value.trim();
  if (!text) { showToast('Укажите формулировку.'); return; }
  issueDiscipline(disciplineTargetId, kind, text);
}

async function initApp() {
  try {
    if (!(await isAuthenticated())) {
      showLoginScreen();
      return;
    }
    hideLoginScreen();
    updateSecurityStrip();
    await loadHrState();
    await loadEvidencePackages();
    if (activeCaseId) expandedEvidenceCaseGroups.add(activeCaseId);
    bootstrapAllCaseGraphs();
    try {
      await ensureCorpMailReady();
    } catch (mailErr) {
      console.error(mailErr);
      await resetCorpMailState();
    }
    updateMailSidebarBadge();
    applyDemoPersona();
    initSidebar();
    showView(resolveInitialView());
    renderCaseDetail(activeCaseId);
  } catch (err) {
    console.error(err);
    clearSession();
    showLoginScreen();
    showToast('Сессия устарела. Войдите снова: ivanov.sp / epsok2028');
  }
}

initStructuresNav();
initApp();

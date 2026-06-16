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
const NOTIFICATIONS_READ_STORAGE = 'epsok-notifications-read';
const EVIDENCE_CUSTODY_STORAGE = 'epsok-evidence-custody';
const VICTIM_NOTIFICATIONS_STORAGE = 'epsok-victim-notifications';
const BOOKMARKS_STORAGE = 'epsok-bookmarks';
const HORIZON_WATCH_STORAGE = 'epsok-horizon-watch';
const HORIZON_COLLISION_STORAGE = 'epsok-horizon-collision';
const WITNESS_PROTECTION_STORAGE = 'epsok-witness-protection';
const SUPPORT_TICKETS_STORAGE = 'epsok-support-tickets';
const TERMINATED_SESSIONS_STORAGE = 'epsok-terminated-sessions';
const HEADER_STATUS_COMPACT_STORAGE = 'epsok-header-status-compact';
const CASES_FILTERS_STORAGE = 'epsok-cases-filters';
const REQUESTS_FILTERS_STORAGE = 'epsok-requests-filters';
const SUSPECTS_FILTERS_STORAGE = 'epsok-suspects-filters';
const AUDIT_FILTERS_STORAGE = 'epsok-audit-filters';

const authUsers = {
  'ivanov.sp': {
    personaId: 'INV_MVD',
    displayName: 'Иванов С.П.',
    contourLabel: 'Следственный комитет · Краснодарский край',
    canSwitchPersona: true
  },
  'sidorov.av': {
    personaId: 'TECH_ADMIN',
    displayName: 'Сидоров А.В.',
    contourLabel: 'Тех. контур · ЦОД',
    canSwitchPersona: false
  },
  'kozlov.va': {
    personaId: 'FUNC_ADMIN',
    displayName: 'Козлов В.А.',
    contourLabel: 'ИТ контур · МВД России',
    canSwitchPersona: false
  },
  'takura.anigatsuki': {
    personaId: 'BETA_TAKURA',
    displayName: 'Такура',
    contourLabel: 'Бета-контур · высший уровень доступа',
    canSwitchPersona: true
  }
};

const PRIVILEGED_PERSONA_IDS = Object.freeze(['TECH_ADMIN', 'FUNC_ADMIN', 'BETA_TAKURA']);

function canSwitchDemoPersona(username = currentUser?.username) {
  if (!username) return false;
  return !!authUsers[username]?.canSwitchPersona;
}

function canUsePersona(personaId, username = currentUser?.username) {
  if (!username || !demoPersonas[personaId]) return false;
  const user = authUsers[username];
  if (!user) return false;
  if (username === 'takura.anigatsuki') return true;
  if (personaId === user.personaId) return true;
  if (PRIVILEGED_PERSONA_IDS.includes(personaId)) return false;
  if (username === 'sidorov.av') return personaId === 'TECH_ADMIN';
  if (username === 'kozlov.va') return personaId === 'FUNC_ADMIN';
  return canSwitchDemoPersona(username);
}

function resolveAllowedPersonaId(personaId, username = currentUser?.username) {
  const user = authUsers[username];
  const fallback = user?.personaId || 'INV_MVD';
  if (personaId && canUsePersona(personaId, username)) return personaId;
  return fallback;
}

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
  func_admin: ['admin', 'profile', 'staff', 'mail'],
  beta_root: ['dashboard', 'cases', 'case', 'graph', 'requests', 'agencies', 'osint', 'horizon', 'deadlines', 'profile', 'staff', 'suspects', 'mail', 'admin']
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
  if (isBetaRootPersona(p)) return 'investigator';
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
      osintHint.innerHTML = 'Надзорный контур · просмотр проверок · запуск недоступен (ПОЛ-006). <button type="button" class="link-btn" onclick="openAccessRequestModal(\'osint_launch\')">Запросить доступ к запуску</button>';
    }
  }
}

function canAccessView(viewId, p = getActivePersona()) {
  return p.allowedViews.includes(viewId);
}

function canSubmitHrRequests(p = getActivePersona()) {
  if (isBetaRootPersona(p)) return true;
  if (isTechAdminPersona(p) || isFuncAdminPersona(p)) return false;
  if (['admin', 'func_admin', 'executor'].includes(p.roleType)) return false;
  return ['inv', 'inv_lead', 'ops', 'prosecutor', 'prosecutor_mil', 'court', 'analyst', 'beta_root'].includes(p.roleType);
}

const ACCESS_FEATURES = {
  cases: { label: 'Реестр дел', policy: 'ПОЛ-001' },
  case: { label: 'Карточка дела', policy: 'ПОЛ-001' },
  graph: { label: 'Граф связей', policy: 'ПОЛ-004' },
  requests: { label: 'Запросы данных', policy: 'ПОЛ-003' },
  osint: { label: 'Открытые источники', policy: 'ПОЛ-006' },
  osint_launch: { label: 'Запуск проверок OSINT', policy: 'ПОЛ-006' },
  horizon: { label: 'Горизонт', policy: 'ПОЛ-007' },
  deadlines: { label: 'Контроль сроков УПК', policy: 'ПОЛ-005' },
  suspects: { label: 'Дела фигурантов', policy: 'ПОЛ-009' },
  staff: { label: 'Кадры', policy: 'ПОЛ-009' },
  hr_self: { label: 'Кадровые заявки', policy: 'ПОЛ-009' },
  agencies: { label: 'Ведомства', policy: 'ПОЛ-003' },
  mail: { label: 'Корпоративная почта', policy: 'ПОЛ-010' }
};

const EPSOK_POLICIES = [
  {
    id: 'POL-001',
    code: 'ПОЛ-001',
    title: 'Кто видит и меняет дело',
    summary: 'Полный доступ — только в рабочей группе. Чужое дело в регионе — просмотр без правок.',
    group: 'investigator',
    scope: 'Дела',
    moduleLabel: 'Реестр дел',
    viewId: 'cases',
    can: ['Редактировать дело, где вы в составе рабочей группы', 'Смотреть хронологию, граф и сроки своих дел', 'Межведомственно открыть карточку в том же регионе — только чтение'],
    cannot: ['Менять дело другого ведомства, если вы не включены в группу', 'Создавать дело за чужое ведомство'],
    example: 'Следователь ФСБ открывает дело МВД в Краснодарском крае — видит карточку, но не может править состав и документы.'
  },
  {
    id: 'POL-002',
    code: 'ПОЛ-002',
    title: 'Надзор прокурора',
    summary: 'Прокурор видит дела поднадзорного региона, но не ведёт следствие в ЕПСОК.',
    group: 'prosecutor',
    scope: 'Прокуратура',
    moduleLabel: 'Реестр дел',
    viewId: 'cases',
    can: ['Читать дела своего региона для надзора', 'Контролировать сроки и процессуальные решения'],
    cannot: ['Менять рабочую группу и материалы дела', 'Отправлять межвед. запросы от имени следствия'],
    example: 'Прокурор открывает дело следователя — только просмотр, без кнопок редактирования.'
  },
  {
    id: 'POL-003',
    code: 'ПОЛ-003',
    title: 'Межведомственные запросы',
    summary: 'Каждый запрос — с правовым основанием. Ответ можно скачать и приложить к делу.',
    group: 'investigator',
    scope: 'Запросы',
    moduleLabel: 'Запросы',
    viewId: 'requests',
    can: ['Направить запрос в другое ведомство через СМЭВ', 'Получить результат и скачать TXT', 'Отслеживать статус и срок ответа'],
    cannot: ['Отправить запрос без постановления или поручения', 'Скрыть факт запроса от журнала аудита'],
    example: 'Запрос в ФНС по 2-НДФЛ: указываете постановление → исполнитель отвечает → «Скачать TXT» в модуле «Запросы».'
  },
  {
    id: 'POL-004',
    code: 'ПОЛ-004',
    title: 'Выгрузка из системы',
    summary: 'Справки по делу, результаты запросов и журнал — только с записью в аудит.',
    group: 'all',
    scope: 'Все',
    moduleLabel: 'Карточка дела',
    viewId: 'case',
    can: ['Скачать справку по делу (TXT) с карточки', 'Выгрузить результат исполненного запроса', 'Экспорт журнала — у администратора ИТ'],
    cannot: ['Массово выгружать данные без служебной необходимости', 'Передавать файлы третьим лицам вне регламента'],
    example: 'На карточке дела — кнопка «Справка по делу (TXT)». Файл сохраняется на диск, действие фиксируется в журнале.'
  },
  {
    id: 'POL-005',
    code: 'ПОЛ-005',
    title: 'Лимит просмотров',
    summary: 'Защита от «пробива» — не более 50 карточек лиц в час на одного пользователя.',
    group: 'all',
    scope: 'Все',
    can: ['Работать с делами и карточками в рамках служебной задачи', 'Видеть предупреждение при приближении к лимиту'],
    cannot: ['Массово открывать карточки без основания', 'Обходить лимит сменой учётной записи'],
    example: 'При превышении лимита система временно блокирует просмотр — обратитесь к руководителю.'
  },
  {
    id: 'POL-006',
    code: 'ПОЛ-006',
    title: 'Открытые источники',
    summary: 'Проверка публичных данных — только с постановлением или поручением.',
    group: 'investigator',
    scope: 'OSINT',
    moduleLabel: 'Открытые источники',
    viewId: 'osint',
    can: ['Запустить проверку e-mail, телефона, ника с указанием основания', 'Импортировать находки в граф дела'],
    cannot: ['Использовать модуль вместо официального запроса в ГИАЦ', 'Запускать проверку без правового основания'],
    example: 'Перед сканированием заполняете поле «Правовое основание» — без него кнопка запуска недоступна.'
  },
  {
    id: 'POL-007',
    code: 'ПОЛ-007',
    title: 'Раскрытие в «Горизонте»',
    summary: 'Федеральные совпадения без единой гражданской БД — персональные данные только по запросу.',
    group: 'pilot',
    scope: 'Горизонт',
    moduleLabel: 'Горизонт',
    viewId: 'horizon',
    can: ['Искать обезличенные совпадения по делам пилота', 'Сформировать черновик межвед. запроса из рекомендации'],
    cannot: ['Видеть ФИО смежного дела без согласования', 'Использовать «Горизонт» как замену ГИАЦ'],
    example: 'Нашли совпадение по кластеру — для раскрытия оформляете межвед. запрос с правовым основанием.'
  },
  {
    id: 'POL-008',
    code: 'ПОЛ-008',
    title: 'Администратор ЦОД',
    summary: 'Технический доступ к сервисам и журналу — без содержимого уголовных дел.',
    group: 'tech',
    scope: 'ЦОД',
    moduleLabel: 'Тех. админ',
    viewId: 'admin',
    can: ['Смотреть статус сервисов, сессии, интеграции СМЭВ', 'Вести журнал аудита и сбор OSINT на уровне контура'],
    cannot: ['Читать хронологию и материалы дел', 'Видеть персональные данные фигурантов'],
    example: 'Тех. админ видит «запрос выполнен», но не видит текст ответа с персональными данными.'
  },
  {
    id: 'POL-009',
    code: 'ПОЛ-009',
    title: 'Кадры и учётные записи',
    summary: 'Заявки на перевод, звание и новые УЗ — по линии подчинения, без самосогласования.',
    group: 'manager',
    scope: 'Кадры',
    moduleLabel: 'Сотрудники',
    viewId: 'staff',
    can: ['Согласовать заявку подчинённого', 'Создать заявку на учётную запись с основанием'],
    cannot: ['Согласовать собственную заявку', 'Назначить роль без указания руководителя'],
    example: 'Следователь подаёт заявку на перевод → руководитель видит её во вкладке «Кадры» и жмёт «Да» или «Нет».'
  },
  {
    id: 'POL-011',
    code: 'ПОЛ-011',
    title: 'Запросить доступ к модулю',
    summary: 'Нет нужного раздела в меню — оформите заявку руководителю с обоснованием.',
    group: 'all',
    scope: 'Все',
    can: ['Нажать «Запросить доступ» в боковом меню', 'Указать дело, постановление или иное основание', 'Получить ответ в корп. почте после согласования'],
    cannot: ['Самостоятельно включить себе «Горизонт» или чужой контур', 'Обойти согласование руководителя'],
    example: 'Нет модуля «Горизонт» — внизу меню «Запросить доступ» → руководитель согласует в «Сотрудники → Кадры».'
  },
  {
    id: 'POL-014',
    code: 'ПОЛ-014',
    title: 'Подключение к «Горизонту»',
    summary: 'Модуль включается по решению ответственного за пилотный регион.',
    group: 'pilot',
    scope: 'Пилот',
    moduleLabel: 'Горизонт',
    viewId: 'horizon',
    can: ['Руководитель СО и пилотные следователи — полный доступ к аналитике', 'Прокурор — надзорный просмотр совпадений'],
    cannot: ['Подключиться самому вне пилотного региона', 'Передать доступ коллеге без заявки ПОЛ-011'],
    example: 'Краснодарский край, Москва, Татарстан — в демо «Горизонт» есть у руководителя; у рядового следователя — после согласования.'
  }
];

const POLICY_GROUP_LABELS = {
  investigator: 'Следователь и дознаватель',
  prosecutor: 'Прокуратура',
  manager: 'Руководитель',
  all: 'Для всех пользователей',
  pilot: 'Пилотные регионы',
  tech: 'ИТ и ЦОД'
};

const POLICY_GROUP_ORDER = ['investigator', 'prosecutor', 'manager', 'all', 'pilot', 'tech'];

const accessRequests = [];
const ACCESS_REQUESTS_STORAGE = 'epsok-access-requests';
const ACCESS_GRANTS_STORAGE = 'epsok-access-grants';
let activeRequestResultId = null;
let activeAccessRequestFeature = null;
let accessRequestSeq = 100;

function shouldOfferAccessRequest(viewId, p = getActivePersona()) {
  if (!ACCESS_FEATURES[viewId]) return false;
  if (isBetaRootPersona(p)) return false;
  if (['admin', 'func_admin'].includes(p.roleType)) return false;
  if (isTechAdminPersona(p) || isFuncAdminPersona(p)) return false;
  return true;
}

function getAccessApproverPersonaId(p = getActivePersona()) {
  const managers = Object.entries(demoPersonas).filter(([, x]) => {
    if (!x.isManager) return false;
    if (x.agency !== p.agency) return false;
    if (p.region && x.region && x.region !== p.region) return false;
    return true;
  });
  if (managers.length) return managers[0][0];
  const anyAgencyManager = Object.entries(demoPersonas).find(([, x]) => x.isManager && x.agency === p.agency);
  if (anyAgencyManager) return anyAgencyManager[0];
  return 'TECH_ADMIN';
}

function getDeniedAccessFeatures(p = getActivePersona()) {
  return Object.keys(ACCESS_FEATURES).filter(key => {
    if (key === 'osint_launch') return canViewOsint(p) && !canLaunchOsintScan(p);
    if (key === 'hr_self') return !canSubmitHrRequests(p);
    return !canAccessView(key, p);
  });
}

function syncAccessRequestLink(p = getActivePersona()) {
  const link = document.getElementById('sidebar-access-request-link');
  if (!link) return;
  const denied = getDeniedAccessFeatures(p);
  const show = denied.length && !['admin', 'func_admin'].includes(p.roleType) && !isTechAdminPersona(p) && !isFuncAdminPersona(p) && !isBetaRootPersona(p);
  link.classList.toggle('hidden', !show);
}

function fillAccessRequestModalFields(featureKey) {
  const meta = ACCESS_FEATURES[featureKey];
  if (!meta) return;
  const title = document.getElementById('access-request-title');
  const featureInput = document.getElementById('access-request-feature');
  const hint = document.getElementById('access-request-hint');
  const approver = demoPersonas[getAccessApproverPersonaId()];
  if (title) title.textContent = `Запрос доступа · ${meta.label}`;
  if (featureInput) featureInput.value = `${meta.label} (${meta.policy})`;
  if (hint) {
    hint.textContent = approver
      ? `Заявка будет направлена: ${approver.name} · ${approver.role}. Укажите постановление, дело или регламент.`
      : 'Укажите правовое или служебное основание — заявка уйдёт руководителю и в журнал аудита.';
  }
}

function openAccessRequestModal(featureKey) {
  const selectWrap = document.getElementById('access-request-feature-wrap');
  const readonlyWrap = document.getElementById('access-request-feature-readonly-wrap');
  const select = document.getElementById('access-request-feature-select');
  const basis = document.getElementById('access-request-basis');
  const context = document.getElementById('access-request-context');
  const p = getActivePersona();

  if (!featureKey) {
    const denied = getDeniedAccessFeatures(p);
    if (!denied.length) {
      showToast('Все модули вашей роли уже доступны.');
      return;
    }
    activeAccessRequestFeature = denied[0];
    selectWrap?.classList.remove('hidden');
    readonlyWrap?.classList.add('hidden');
    if (select) {
      select.innerHTML = denied.map(k => `<option value="${k}">${ACCESS_FEATURES[k].label} (${ACCESS_FEATURES[k].policy})</option>`).join('');
      select.value = denied[0];
      select.onchange = () => {
        activeAccessRequestFeature = select.value;
        fillAccessRequestModalFields(select.value);
      };
    }
  } else {
    if (!ACCESS_FEATURES[featureKey]) return;
    activeAccessRequestFeature = featureKey;
    selectWrap?.classList.add('hidden');
    readonlyWrap?.classList.remove('hidden');
  }

  fillAccessRequestModalFields(activeAccessRequestFeature);
  if (basis) basis.value = '';
  if (context) context.value = activeCaseId && personaCanBrowseCase(activeCaseId) ? activeCaseId : '';
  document.getElementById('access-request-modal')?.classList.remove('hidden');
}

function closeAccessRequestModal() {
  activeAccessRequestFeature = null;
  document.getElementById('access-request-modal')?.classList.add('hidden');
}

async function submitAccessRequest() {
  const select = document.getElementById('access-request-feature-select');
  const featureKey = activeAccessRequestFeature || select?.value;
  const meta = ACCESS_FEATURES[featureKey];
  const basisType = document.getElementById('access-request-basis-type')?.value || 'other';
  const basisText = document.getElementById('access-request-basis')?.value.trim();
  const context = document.getElementById('access-request-context')?.value.trim();
  if (!meta || !basisText) {
    showToast('Укажите обоснование запроса доступа.');
    return;
  }
  const p = getActivePersona();
  const approverId = getAccessApproverPersonaId(p);
  accessRequestSeq += 1;
  const id = `Доступ-${accessRequestSeq}`;
  const basisLabels = {
    order: 'Постановление / поручение',
    case: 'Связь с делом',
    law: 'Регламент / ПОЛ',
    pilot: 'Пилот / кластер',
    other: 'Служебное основание'
  };
  accessRequests.unshift({
    id,
    featureKey,
    featureLabel: meta.label,
    policy: meta.policy,
    basisType,
    basis: basisText,
    context: context || undefined,
    requestorPersonaId: p.id,
    approverPersonaId: approverId,
    status: 'pending',
    sent: formatRequestNow()
  });
  saveAccessRequests();
  pushAuditEntry('Заявка на доступ', `${id} · ${meta.label}`, meta.policy);
  closeAccessRequestModal();
  await pushEpsokSystemMail({
    toPersonaId: approverId,
    subject: `[ЕПСОК] Заявка на доступ · ${meta.label}`,
    body: `Запрос расширения полномочий.\n\nID: ${id}\nСотрудник: ${p.name} · ${p.department || p.group}\nМодуль: ${meta.label} (${meta.policy})\nОснование: ${basisLabels[basisType] || basisType}\n\n${basisText}${context ? `\nКонтекст: ${context}` : ''}\n\nСогласование — в контуре кадров / руководителя.`
  });
  showToast(`${id}: заявка на «${meta.label}» направлена руководителю`);
}

function loadAccessRequests() {
  try {
    const data = JSON.parse(localStorage.getItem(ACCESS_REQUESTS_STORAGE) || '[]');
    accessRequests.length = 0;
    data.forEach(r => accessRequests.push(r));
    const maxId = accessRequests.reduce((m, r) => {
      const n = parseInt(String(r.id).replace(/\D/g, ''), 10);
      return Number.isFinite(n) ? Math.max(m, n) : m;
    }, 100);
    accessRequestSeq = Math.max(accessRequestSeq, maxId + 1);
  } catch { /* demo */ }
}

function saveAccessRequests() {
  localStorage.setItem(ACCESS_REQUESTS_STORAGE, JSON.stringify(accessRequests));
}

function featureKeyToViewId(featureKey) {
  if (featureKey === 'osint_launch' || featureKey === 'hr_self') return featureKey === 'osint_launch' ? 'osint' : 'profile';
  return featureKey;
}

function loadAccessGrants() {
  try { return JSON.parse(localStorage.getItem(ACCESS_GRANTS_STORAGE) || '{}'); }
  catch { return {}; }
}

function saveAccessGrant(personaId, featureKey) {
  const grants = loadAccessGrants();
  if (!grants[personaId]) grants[personaId] = [];
  const viewId = featureKeyToViewId(featureKey);
  if (!grants[personaId].includes(viewId)) grants[personaId].push(viewId);
  localStorage.setItem(ACCESS_GRANTS_STORAGE, JSON.stringify(grants));
}

function applyAccessGrants(persona) {
  if (!persona) return persona;
  const extra = loadAccessGrants()[persona.id];
  if (!extra?.length) return persona;
  return {
    ...persona,
    allowedViews: [...new Set([...persona.allowedViews, ...extra])]
  };
}

function canReviewAccessRequest(viewer, req) {
  if (!req || req.status !== 'pending') return false;
  if (viewer.id === req.approverPersonaId) return true;
  const requestor = demoPersonas[req.requestorPersonaId];
  if (!requestor) return false;
  return isPersonnelManager(viewer) && viewer.agency === requestor.agency && viewer.region === requestor.region;
}

function getPendingAccessRequestsForViewer(viewer) {
  return accessRequests.filter(r => canReviewAccessRequest(viewer, r));
}

async function managerApproveAccess(requestId, approved) {
  const req = accessRequests.find(r => r.id === requestId);
  const viewer = getActivePersona();
  if (!canReviewAccessRequest(viewer, req)) {
    showToast('Нет полномочий на согласование этой заявки.');
    return;
  }
  req.status = approved ? 'approved' : 'rejected';
  req.reviewedAt = formatRequestNow();
  req.reviewerPersonaId = viewer.id;
  saveAccessRequests();
  pushAuditEntry(
    approved ? 'Согласование доступа' : 'Отклонение доступа',
    `${req.id} · ${req.featureLabel}`,
    req.policy
  );
  await pushEpsokSystemMail({
    toPersonaId: req.requestorPersonaId,
    subject: `[ЕПСОК] ${approved ? 'Доступ согласован' : 'Отказ в доступе'} · ${req.featureLabel}`,
    body: `${approved ? 'Согласовано' : 'Отклонено'} руководителем ${viewer.name}.\n\nID: ${req.id}\nМодуль: ${req.featureLabel} (${req.policy})\nОснование: ${req.basis}${req.context ? `\nКонтекст: ${req.context}` : ''}`
  });
  if (approved) {
    saveAccessGrant(req.requestorPersonaId, req.featureKey);
    if (activePersonaId === req.requestorPersonaId) applyDemoPersona();
  }
  renderStaff();
  refreshHeaderChrome();
  showToast(approved ? `${req.id}: доступ согласован` : `${req.id}: в доступе отказано`);
}

function renderStaffAccessRequestsPanel(viewer) {
  const pending = getPendingAccessRequestsForViewer(viewer);
  if (!pending.length) return '';
  return `<div class="panel panel-table" style="margin-bottom:1rem">
    <h3>Заявки на доступ (ПОЛ-011)</h3>
    <div class="table-scroll"><table class="data-table"><thead><tr><th>№</th><th>Сотрудник</th><th>Модуль</th><th>Основание</th><th></th></tr></thead><tbody>
      ${pending.map(r => {
        const s = demoPersonas[r.requestorPersonaId];
        return `<tr>
          <td>${r.id}</td>
          <td>${escapeHtml(s?.name || '—')}</td>
          <td>${escapeHtml(r.featureLabel)}<br><span class="muted">${escapeHtml(r.policy)}</span></td>
          <td class="muted">${escapeHtml(r.basis)}</td>
          <td><button class="btn-xs approve" onclick="managerApproveAccess('${r.id}',true)">Да</button> <button class="btn-xs reject" onclick="managerApproveAccess('${r.id}',false)">Нет</button></td>
        </tr>`;
      }).join('')}
    </tbody></table></div>
    <p class="muted" style="margin-top:0.75rem;font-size:0.8rem">ПОЛ-011: согласование расширения полномочий · уведомление в корп. почту · запись в журнал аудита.</p>
  </div>`;
}

function isCaseReadOnly(p = getActivePersona(), caseId = activeCaseId) {
  if (isBetaRootPersona(p)) return false;
  if (caseId && !personaCanAccessCase(caseId)) return true;
  return ['prosecutor', 'prosecutor_mil', 'analyst', 'court'].includes(p.roleType);
}

function personaCanBrowseCase(caseId) {
  if (personaCanAccessCase(caseId)) return true;
  const c = getCaseById(caseId);
  if (!c) return false;
  const p = getActivePersona();
  if (!canAccessView('case', p)) return false;
  const region = p.caseScope?.region || p.region;
  if (!region || c.region !== region) return false;
  if (['prosecutor', 'prosecutor_mil', 'court', 'analyst'].includes(p.roleType)) return true;
  return getCaseJurisdictionScope(c, p) === 'interagency';
}

function getCaseAccessMode(caseId) {
  if (personaCanAccessCase(caseId)) {
    const p = getActivePersona();
    if (isBetaRootPersona(p)) {
      return { mode: 'member', readonly: false };
    }
    if (['prosecutor', 'prosecutor_mil', 'analyst', 'court'].includes(p.roleType)) {
      return { mode: 'supervisory', readonly: true };
    }
    return { mode: 'member', readonly: false };
  }
  if (personaCanBrowseCase(caseId)) return { mode: 'interagency', readonly: true };
  return { mode: 'denied', readonly: true };
}

function explainCaseAccess(caseId) {
  const c = getCaseById(caseId);
  const p = getActivePersona();
  const access = getCaseAccessMode(caseId);
  const region = p.caseScope?.region || p.region;
  const inRegion = !!(c && region && c.region === region);
  const facts = [];
  let policy = 'ПОЛ-001';
  let title = 'Доступ';
  let canDo = [];
  let cannotDo = [];
  let action = null;

  if (!c) {
    return { title: 'Дело не найдено', facts: ['Карточка отсутствует в реестре'], policy, canDo: [], cannotDo: [], mode: 'denied', action: null };
  }

  if (access.mode === 'member') {
    title = 'Полный доступ к делу';
    facts.push('Вы в рабочей группе или ответственный по делу');
    facts.push(`${c.agencyName} · ${c.region} · ${c.department}`);
    canDo = ['Редактировать состав РГ', 'Межвед. и внутр. запросы', 'Экспорт справки и пакета'];
    cannotDo = [];
    policy = 'ПОЛ-001';
  } else if (access.mode === 'interagency') {
    title = 'Межведомственный просмотр';
    facts.push(`Дело ведёт ${c.agencyName} · отв. ${c.lead}`);
    facts.push(`Ваше ведомство: ${p.agency || p.group} — вы не в рабочей группе`);
    facts.push(`Регион дела: ${c.region}${inRegion ? ' (совпадает с вашим)' : ''}`);
    canDo = ['Карточка и хронология (чтение)', 'Граф связей (чтение)', 'Сроки УПК'];
    cannotDo = ['Изменение состава', 'Редактирование материалов', 'Запросы от имени ведущего ведомства'];
    action = { label: 'Запросить включение в РГ', onclick: `openCaseTeamAccessRequest('${caseId}')` };
    policy = 'ПОЛ-001';
  } else if (access.mode === 'supervisory') {
    title = 'Надзорный контур';
    facts.push(`Роль: ${p.role || p.roleType} · регион ${region || '—'}`);
    facts.push(`Дело: ${c.article} · ${c.agencyName}`);
    canDo = ['Просмотр карточки', 'Контроль сроков УПК', 'Экспорт для надзора'];
    cannotDo = ['Изменение дела', 'Запросы следствия'];
    policy = 'ПОЛ-002';
  } else {
    title = 'Доступ закрыт';
    if (!inRegion) facts.push(`Дело в регионе «${c.region}» · ваш: «${region || 'не указан'}»`);
    if (!sameCaseAgency(c, p)) facts.push(`Ведомство дела — ${c.agencyName}, не ваш контур`);
    facts.push('Нет членства в РГ и нет права межвед. просмотра');
    cannotDo = ['Карточка', 'Граф', 'Экспорт'];
    canDo = [];
    policy = 'ПОЛ-001';
  }

  return { title, facts, policy, canDo, cannotDo, mode: access.mode, action };
}

const CASE_PROVENANCE_STORAGE = 'epsok-case-provenance-v1';

function loadAllCaseProvenance() {
  try { return JSON.parse(localStorage.getItem(CASE_PROVENANCE_STORAGE) || '{}'); }
  catch { return {}; }
}

function saveAllCaseProvenance(data) {
  localStorage.setItem(CASE_PROVENANCE_STORAGE, JSON.stringify(data));
}

function getDefaultCaseProvenance(caseId) {
  const c = getCaseById(caseId);
  if (!c) return [];
  const seed = [
    { at: c.opened || '—', type: 'registration', source: 'Регистрация дела', detail: `Возбуждено · ${c.article} · ${c.crimeType}`, policy: 'ПОЛ-001', actor: c.lead, graphNodeIds: ['p1', 'c1'] }
  ];
  (c.timeline || []).slice(0, 2).forEach(t => {
    seed.push({ at: t.date, type: 'timeline', source: 'Хронология', detail: t.text, policy: 'ПОЛ-001', actor: c.lead, graphNodeIds: ['p1', 'ph1'] });
  });
  return seed;
}

function getCaseProvenance(caseId) {
  const all = loadAllCaseProvenance();
  return all[caseId] || getDefaultCaseProvenance(caseId);
}

function pushCaseProvenance(caseId, entry) {
  if (!caseId) return;
  const all = loadAllCaseProvenance();
  if (!all[caseId]) all[caseId] = getDefaultCaseProvenance(caseId);
  const enriched = { ...entry };
  if (!enriched.graphNodeIds?.length) {
    enriched.graphNodeIds = inferProvenanceGraphNodes(caseId, enriched);
  }
  all[caseId].unshift({
    at: formatAuditTimestamp?.() || new Date().toLocaleString('ru-RU'),
    actor: getActivePersona()?.name || 'система',
    ...enriched
  });
  if (all[caseId].length > 80) all[caseId].length = 80;
  saveAllCaseProvenance(all);
}

function inferProvenanceGraphNodes(caseId, entry) {
  const detail = (entry.detail || '').toLowerCase();
  const ids = [];
  const add = id => { if (id && !ids.includes(id)) ids.push(id); };
  if (entry.type === 'registration' || entry.type === 'timeline') {
    graphNodes.filter(n => n.caseId === caseId && (n.type === 'person' || n.type === 'case')).forEach(n => add(n.id));
  }
  if (entry.type === 'request' || entry.type === 'result' || detail.includes('фнс') || detail.includes('2-ндфл') || detail.includes('егрюл')) {
    add('org1'); add('acc1');
  }
  if (detail.includes('cdr') || detail.includes('sim') || detail.includes('телефон') || entry.type === 'horizon') {
    graphNodes.filter(n => n.type === 'phone' && (n.caseId === caseId || entry.type === 'horizon')).forEach(n => add(n.id));
  }
  if (entry.type === 'horizon' || detail.includes('раскрытие') || detail.includes('совпаден')) {
    add('ph2'); add('c2'); add('c3');
  }
  if (entry.type === 'team') add('p1');
  if (!ids.length) {
    graphNodes.filter(n => n.caseId === caseId).slice(0, 3).forEach(n => add(n.id));
  }
  return ids;
}

function jumpToProvenanceGraph(caseId, index) {
  const entry = getCaseProvenance(caseId)[index];
  if (!entry) return;
  const nodeIds = entry.graphNodeIds?.length ? entry.graphNodeIds : inferProvenanceGraphNodes(caseId, entry);
  if (!nodeIds.length) {
    showToast('Для этой записи нет привязки к графу.');
    return;
  }
  openCaseGraph(caseId);
  setTimeout(() => {
    graphView.highlightProvenanceNodes(nodeIds);
    graphView.selectNodeById(nodeIds[0]);
    showToast(`Граф: подсвечено ${nodeIds.length} узл. · ${entry.source}`);
  }, 250);
}

function renderAccessExplainPanel(caseId) {
  const ex = explainCaseAccess(caseId);
  const access = getCaseAccessMode(caseId);
  if (!access.readonly && access.mode === 'member') return '';

  const factsHtml = ex.facts.map(f => `<li>${escapeHtml(f)}</li>`).join('');
  const canHtml = ex.canDo.length ? `<div class="access-explain-col"><span class="access-explain-label">Можно</span><ul>${ex.canDo.map(x => `<li>${escapeHtml(x)}</li>`).join('')}</ul></div>` : '';
  const cannotHtml = ex.cannotDo.length ? `<div class="access-explain-col"><span class="access-explain-label">Нельзя</span><ul>${ex.cannotDo.map(x => `<li>${escapeHtml(x)}</li>`).join('')}</ul></div>` : '';
  const actionBtn = ex.action
    ? `<button type="button" class="btn-sm" onclick="${ex.action.onclick}">${escapeHtml(ex.action.label)}</button>`
    : '';

  return `<aside class="access-explain-panel mode-${ex.mode}" role="status">
    <div class="access-explain-head">
      <strong>${escapeHtml(ex.title)}</strong>
      <span class="link-badge">${escapeHtml(ex.policy)}</span>
    </div>
    <p class="muted access-explain-lead">Почему так:</p>
    <ul class="access-explain-facts">${factsHtml}</ul>
    <div class="access-explain-cols">${canHtml}${cannotHtml}</div>
    ${actionBtn ? `<div class="access-explain-actions">${actionBtn}</div>` : ''}
  </aside>`;
}

function renderCaseReadonlyBanner(caseId) {
  return renderAccessExplainPanel(caseId);
}

function openCaseTeamAccessRequest(caseId) {
  openAccessRequestModal('case');
  const ctx = document.getElementById('access-request-context');
  const c = getCaseById(caseId);
  if (ctx && c) {
    ctx.value = `Включение в рабочую группу · ${caseId} · ${c.article} · ${c.agencyName} · отв. ${c.lead}`;
  }
}

function renderCaseProvenanceSection(c) {
  const rows = getCaseProvenance(c.id);
  if (!rows.length) return '';
  const items = rows.slice(0, 12).map((r, i) => {
    const hasGraph = (r.graphNodeIds?.length || inferProvenanceGraphNodes(c.id, r).length) > 0;
    const graphBtn = hasGraph
      ? `<button type="button" class="link-btn provenance-graph-link" onclick="jumpToProvenanceGraph('${c.id}',${i})">На графе →</button>`
      : '';
    return `
    <li class="provenance-item${hasGraph ? ' provenance-item-linked' : ''}">
      <span class="provenance-time">${escapeHtml(r.at)}</span>
      <div class="provenance-body">
        <strong>${escapeHtml(r.source)}</strong>
        <span class="muted"> · ${escapeHtml(r.actor)}</span>
        <p>${escapeHtml(r.detail)}</p>
        <span class="link-badge">${escapeHtml(r.policy || 'ПОЛ-004')}</span>
        ${graphBtn}
      </div>
    </li>`;
  }).join('');
  return `<div class="panel case-provenance-panel">
    <div class="panel-header case-provenance-head">
      <h2>Цепочка происхождения</h2>
      <button type="button" class="btn-sm" onclick="downloadCaseProvenanceTxt('${c.id}')">Цепочка (TXT)</button>
    </div>
    <p class="muted case-provenance-hint">Откуда в деле появились сведения · фиксация для надзора и суда (ПОЛ-004)</p>
    <ol class="provenance-list">${items}</ol>
  </div>`;
}

function buildCaseProvenanceDocument(caseId) {
  const c = getCaseById(caseId);
  const rows = getCaseProvenance(caseId);
  if (!c || !rows.length) return '';
  const lines = [
    'ЕПСОК · ЦЕПОЧКА ПРОИСХОЖДЕНИЯ СВЕДЕНИЙ',
    '========================================',
    `Дело: ${caseId}`,
    `Статья: ${c.article} · ${c.crimeType}`,
    `Ведомство: ${c.agencyName} · ${c.region}`,
    `Сформировано: ${new Date().toLocaleString('ru-RU')}`,
    '',
    'ЗАПИСИ (от новых к старым)',
    '---------------------------'
  ];
  rows.forEach((r, i) => {
    lines.push(`${i + 1}. [${r.at}] ${r.source} · ${r.actor}`);
    lines.push(`   ${r.detail}`);
    lines.push(`   Политика: ${r.policy || 'ПОЛ-004'}`);
    lines.push('');
  });
  return lines.join('\n');
}

function downloadCaseProvenanceTxt(caseId) {
  const access = getCaseAccessMode(caseId);
  if (access.mode === 'denied') {
    showToast('ПОЛ-001: нет доступа к выгрузке.');
    return;
  }
  const body = buildCaseProvenanceDocument(caseId);
  if (!body) {
    showToast('Нет записей в цепочке происхождения.');
    return;
  }
  downloadTextFile(`${caseId}-provenance.txt`, appendDemoExportSignatureBlock(body));
  pushAuditEntry('Экспорт цепочки происхождения', caseId, 'ПОЛ-004');
  pushCaseProvenance(caseId, { type: 'export', source: 'Экспорт', detail: 'Цепочка происхождения (TXT)', policy: 'ПОЛ-004' });
  showToast(`Цепочка сохранена: ${sanitizeDownloadFilename(`${caseId}-provenance.txt`)}`);
}

function renderCaseQuickLinksHtml(c) {
  const p = getActivePersona();
  if (!personaCanBrowseCase(c.id)) return '';
  const browseOnly = !personaCanAccessCase(c.id);
  const btns = [];
  if (canAccessView('graph', p)) {
    btns.push(`<button type="button" class="btn-sm case-quick-link" onclick="openCaseGraph('${c.id}')"><span class="case-quick-icon" aria-hidden="true">◎</span> Граф связей</button>`);
  }
  if (canAccessView('deadlines', p)) {
    btns.push(`<button type="button" class="btn-sm case-quick-link" onclick="openCaseDeadlines('${c.id}')"><span class="case-quick-icon" aria-hidden="true">⏱</span> Сроки УПК</button>`);
  }
  if (canAccessView('horizon', p) && !browseOnly) {
    btns.push(`<button type="button" class="btn-sm case-quick-link" onclick="selectHorizonCase('${c.id}');showView('horizon')"><span class="case-quick-icon" aria-hidden="true">◈</span> Горизонт</button>`);
  }
  if (canViewOsint(p)) {
    btns.push(`<button type="button" class="btn-sm case-quick-link" onclick="openCaseOsint('${c.id}')"><span class="case-quick-icon" aria-hidden="true">⌕</span> Открытые источники</button>`);
    if (canLaunchOsintScan(p) && !browseOnly) {
      btns.push(`<button type="button" class="btn-sm case-quick-link" onclick="scrollToEvidencePackages()"><span class="case-quick-icon" aria-hidden="true">▣</span> Пакеты доказательств</button>`);
    }
  }
  if (c.cluster && (canAccessView('graph', p) || canAccessView('horizon', p))) {
    btns.push(`<button type="button" class="btn-sm case-quick-link" onclick="openClusterHub('${escapeHtml(c.cluster)}')"><span class="case-quick-icon" aria-hidden="true">◫</span> Кластер ${escapeHtml(c.cluster)}</button>`);
  }
  if (!btns.length) return '';
  return `<div class="case-quick-links">${btns.join('')}</div>`;
}

function openCaseDeadlines(caseId) {
  if (!personaCanBrowseCase(caseId)) {
    showToast('ПОЛ-001: нет доступа к этому делу для текущей роли.');
    return;
  }
  activeCaseId = caseId;
  activeDeadlinesCaseId = caseId;
  updateHeaderContext();
  showView('deadlines');
}

function openCaseOsint(caseId) {
  if (!personaCanBrowseCase(caseId)) {
    showToast('ПОЛ-001: нет доступа к этому делу для текущей роли.');
    return;
  }
  activeCaseId = caseId;
  updateHeaderContext();
  showView('osint');
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
    dashboardMode: 'court',
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
  INV_MVD_ANDREEV_DEMO: enrichPersona({
    id: 'INV_MVD_ANDREEV_DEMO',
    roleType: 'inv',
    group: 'МВД России',
    avatar: 'АС',
    name: 'Андреев С.В.',
    role: 'Следователь · СО №1',
    department: 'СО №1 по Прикубанскому округу',
    agency: 'МВД',
    region: 'Краснодарский край',
    headerContour: 'Следственный комитет',
    contourSub: 'Краснодарский край · СО №1 · МВД',
    dashboardTitle: 'Дашборд следователя',
    dashboardMode: 'investigator',
    defaultView: 'cases',
    caseScope: { agency: 'МВД', region: 'Краснодарский край' }
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
  }),
  BETA_TAKURA: enrichPersona({
    id: 'BETA_TAKURA',
    roleType: 'beta_root',
    adminKind: 'tech',
    isManager: true,
    group: 'ЕПСОК · бета',
    avatar: 'ТК',
    name: 'Такура',
    role: 'Высший уровень доступа · бета',
    department: 'Пилотный контур · федеральный доступ',
    agency: 'МВД',
    region: 'Федеральный',
    headerContour: 'Бета-контур',
    contourSub: 'Полный доступ · все модули · тестирование',
    dashboardTitle: 'Дашборд · высший уровень доступа',
    dashboardMode: 'investigator',
    defaultView: 'dashboard',
    caseScope: null
  })
};

const demoPersonaGroups = [
  { label: 'Бета-тест · полный доступ', ids: ['BETA_TAKURA'] },
  { label: 'МВД России', ids: ['INV_LEAD_MVD', 'INV_MVD', 'INV_MVD_KOVALEV', 'INV_MVD_ANDREEV_DEMO', 'INV_MVD_NOVIKOV', 'INV_LEAD_MVD_WEST', 'INV_MVD_SEMYONOVA', 'INV_MVD_ROSTOV', 'OPS_LEAD_MVD', 'OPS_MVD', 'OPS_MVD_2', 'OPS_MVD_3', 'EXEC_MVD', 'FUNC_ADMIN'] },
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
  draft: 'Черновик',
  rejected: 'Отклонён',
  expired: 'Истёк срок'
};

const platformRequests = [
  { id: 'Запрос-88421', scope: 'interagency', type: 'Движение средств', subject: 'Иванов А.С., счёт ***8842', target: 'Росфинмониторинг', from: 'МВД · СО №3 · Краснодар', agency: 'Росфинмониторинг', status: 'fulfilled', sent: '02.02.2028', sla: '1,2 дня ✓' },
  { id: 'Запрос-88422', scope: 'interagency', type: 'Выписка ЕГРЮЛ', subject: 'ООО «СеверТрейд», ИНН 7701234567', target: 'ФНС', from: 'СК · Москва', agency: 'ФНС', status: 'fulfilled', sent: '03.02.2028', sla: '0,8 дня ✓' },
  { id: 'Запрос-88450', scope: 'intra_agency', type: 'Проверка по ГИАЦ', subject: 'Петров В.Г., 15.03.1985', target: 'ГИАЦ · Краснодарский край', from: 'СО №3 по Центральному району', agency: 'МВД', status: 'progress', sent: '14.06.2028', sla: 'ост. 4 ч' },
  { id: 'Запрос-88451', scope: 'intra_agency', type: 'Назначение экспертизы', target: 'ЦЭК МВД · ЮФО', from: 'СО №3 · Краснодар', agency: 'МВД', status: 'submitted', sent: '13.06.2028', sla: '3 дня' },
  { id: 'Запрос-88452', scope: 'intra_agency', type: 'Смежное СО', target: 'СО №1 · Прикубанский район', from: 'СО №3 · Краснодар', agency: 'МВД', status: 'progress', sent: '12.06.2028', sla: '1 день' },
  { id: 'Запрос-88460', scope: 'intra_department', type: 'Оперативная справка', target: 'ОУР №4 (прикреплён)', from: 'СО №3 · следователь', agency: 'МВД', department: 'СО №3 по Центральному району', status: 'fulfilled', sent: '11.06.2028', sla: '2 ч ✓' },
  { id: 'Запрос-88461', scope: 'intra_department', type: 'Согласование следственного действия', target: 'Руководитель СО №3', from: 'СО №3 · следователь', agency: 'МВД', department: 'СО №3 по Центральному району', status: 'progress', sent: '14.06.2028', sla: 'ост. 1 ч' },
  { id: 'Запрос-88462', scope: 'intra_department', type: 'Передача материалов', target: 'Опергруппа СО №3', from: 'СО №3 · следователь', agency: 'МВД', department: 'СО №3 по Центральному району', status: 'submitted', sent: '13.06.2028', sla: '4 ч' },
  { id: 'Запрос-88501', scope: 'interagency', type: 'Проверка по базам', target: 'МВД (ГИАЦ)', from: 'МВД · Краснодар', agency: 'МВД (ГИАЦ)', district: 'Центральный район', targetDepartment: 'ГИАЦ · Краснодарский край', status: 'progress', sent: '14.06.2028', sla: 'ост. 2 ч' },
  { id: 'Запрос-88502', scope: 'interagency', type: 'Смежное дело', target: 'СК РФ', from: 'МВД · Ростов', agency: 'СК РФ', district: 'Октябрьский район', targetDepartment: 'СУ СК по Ростовской области', status: 'submitted', sent: '14.06.2028', sla: '1 день' },
  { id: 'Запрос-88503', scope: 'interagency', type: 'УДО / ФСИН', target: 'ФСИН', from: 'СК · Ростов', agency: 'ФСИН', status: 'draft', sent: '—', sla: '196-ФЗ' },
  { id: 'Запрос-88504', scope: 'interagency', type: 'Разрешение на оружие', target: 'Росгвардия', from: 'МВД · Ставрополь', agency: 'Росгвардия', status: 'progress', sent: '13.06.2028', sla: '150-ФЗ' },
  { id: 'Запрос-88505', scope: 'interagency', type: 'Исполнительный лист', target: 'ФССП', from: 'СК · Краснодар', agency: 'ФССП', status: 'progress', sent: '14.06.2028', sla: '229-ФЗ' },
  { id: 'Запрос-88506', scope: 'interagency', type: 'Выписка ЕГРН', target: 'Росреестр', from: 'МВД · Москва', agency: 'Росреестр', status: 'submitted', sent: '13.06.2028', sla: '2 дня' },
  { id: 'Запрос-88507', scope: 'intra_agency', type: 'Судебная экспертиза', target: 'Экспертное управление СК', from: 'СУ по ЮВАО', agency: 'СК', status: 'progress', sent: '14.06.2028', sla: '5 дней' },
  { id: 'Запрос-88508', scope: 'intra_agency', type: 'Запрос в управление ОРД', target: 'Управление контрразведки УФСБ', from: 'Следственный отдел УФСБ', agency: 'ФСБ', status: 'submitted', sent: '12.06.2028', sla: '40-ФЗ' },
  { id: 'Запрос-88509', scope: 'intra_department', type: 'Согласование выезда', target: 'Руководитель УФСБ', from: 'Следователь УФСБ', agency: 'ФСБ', department: 'УФСБ по Краснодарскому краю', status: 'fulfilled', sent: '10.06.2028', sla: '1 ч ✓' },
  { id: 'Запрос-88510', scope: 'interagency', type: 'Таможенная декларация', target: 'ФТС', from: 'ФТС · Москва', agency: 'ФТС', status: 'fulfilled', sent: '10.06.2028', sla: '1,5 дня ✓' },
  { id: 'Запрос-88511', scope: 'intra_agency', type: 'Смежное таможенное СО', target: 'Таможня Домодедово', from: 'Таможня Шереметьево', agency: 'ФТС', status: 'progress', sent: '13.06.2028', sla: '1 день' },
  { id: 'Запрос-88512', scope: 'interagency', type: 'Запрос по операциям', target: 'ЦБ', from: 'МВД · Краснодар', agency: 'ЦБ', status: 'progress', sent: '14.06.2028', sla: 'ост. 1 день' },
  { id: 'Запрос-88440', scope: 'interagency', type: '2-НДФЛ', subject: 'Подозреваемый А. · ЕПСОК-2028-004521', target: 'ФНС', from: 'СО №3 по Центральному району · Иванов', agency: 'ФНС', district: 'Центральный район', targetDepartment: 'МИ ФНС №23 по Краснодарскому краю', region: 'Краснодарский край', requestorPersonaId: 'INV_MVD', legal: 'Постановление №142 · дело ЕПСОК-2028-004521', status: 'rejected', sent: '28.05.2028', sla: 'отклонён', retryCount: 0 },
  { id: 'Запрос-88441', scope: 'interagency', type: 'Сведения о счетах', subject: 'Счёт ***8842 · ЕПСОК-2028-004521', target: 'ФНС', from: 'СО №3 по Центральному району · Иванов', agency: 'ФНС', district: 'Центральный район', targetDepartment: 'МИ ФНС №23 по Краснодарскому краю', region: 'Краснодарский край', requestorPersonaId: 'INV_MVD', legal: 'Постановление №142 · дело ЕПСОК-2028-004521', status: 'expired', sent: '01.06.2028', sla: 'истёк', retryCount: 0 }
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
  const base = demoPersonas[activePersonaId] || demoPersonas.INV_MVD;
  return applyAccessGrants(base);
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
  const safePersonaId = resolveAllowedPersonaId(personaId, username);
  const inner = { personaId: safePersonaId, at: Date.now() };
  if (personaExplicit && safePersonaId === personaId) inner.personaExplicit = true;
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
  const boot = resolveAppBootNavigation(p);
  return boot.view;
}

function parseAppLocationHash() {
  const raw = (location.hash || '').replace(/^#/, '').trim();
  if (!raw) return null;
  const params = new URLSearchParams(raw);
  const san = (v) => (typeof EpsokSecurity?.sanitizeDeepLinkValue === 'function'
    ? EpsokSecurity.sanitizeDeepLinkValue(v)
    : (v ? String(v).trim().slice(0, 80) : null));
  return {
    view: san(params.get('view')),
    caseId: san(params.get('case')),
    requestId: san(params.get('request')),
    suspectId: san(params.get('suspect')),
    clusterId: san(params.get('cluster'))
  };
}

function resolveAppBootNavigation(p = getActivePersona()) {
  const link = parseAppLocationHash();
  if (link?.caseId && getCaseById(link.caseId) && personaCanBrowseCase(link.caseId)) {
    activeCaseId = link.caseId;
    activeDeadlinesCaseId = link.caseId;
    if (getCaseById(link.caseId)?.cluster || getCaseById(link.caseId)?.related?.length) {
      activeHorizonCaseId = link.caseId;
    }
  }
  if (link?.requestId && getRequestById(link.requestId)) {
    activeRequestHighlightId = link.requestId;
  }
  if (link?.suspectId) {
    activeSuspectId = link.suspectId;
  }
  if (link?.clusterId) {
    activeClusterHubId = link.clusterId;
  }
  if (link?.view && isViewAllowedForPersona(link.view, p)) {
    if (link.view === 'agencies' && link.clusterId) {
      setTimeout(() => openClusterHub(link.clusterId), 0);
    }
    return { view: link.view, fromHash: true };
  }
  if (link?.caseId && personaCanBrowseCase(link.caseId)) {
    return { view: 'case', fromHash: true };
  }
  if (link?.clusterId && !link?.view) {
    setTimeout(() => openClusterHub(link.clusterId), 0);
    return { view: 'dashboard', fromHash: true };
  }
  const saved = getSavedActiveView();
  if (saved && isViewAllowedForPersona(saved, p)) return { view: saved, fromHash: false };
  return { view: 'dashboard', fromHash: false };
}

function syncAppDeepLinkHash({ view, caseId, requestId, suspectId, clusterId } = {}) {
  if (!isAppLoggedIn()) return;
  const params = new URLSearchParams();
  const v = view || null;
  const c = caseId || (v === 'case' ? activeCaseId : (v === 'deadlines' ? activeDeadlinesCaseId : null));
  const req = requestId || (v === 'requests' ? activeRequestHighlightId : null);
  const sus = suspectId || (v === 'suspects' ? activeSuspectId : null);
  const cl = clusterId || null;
  if (v && v !== 'dashboard') params.set('view', v);
  if (c) params.set('case', c);
  if (req) params.set('request', req);
  if (sus) params.set('suspect', sus);
  if (cl) params.set('cluster', cl);
  const next = params.toString();
  const hash = next ? `#${next}` : '';
  if (location.hash !== hash) {
    history.replaceState(null, '', `${location.pathname}${location.search}${hash}`);
  }
}

async function copyCaseReference(caseId) {
  const c = getCaseById(caseId);
  if (!c) return;
  const params = new URLSearchParams({ case: caseId, view: 'case' });
  const url = `${location.origin}${location.pathname}#${params.toString()}`;
  const text = `ЕПСОК ${caseId} · ${c.article}\n${url}`;
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
    } else {
      throw new Error('clipboard');
    }
    pushAuditEntry('Копирование ссылки на дело', caseId, 'ПОЛ-001');
    showToast('Ссылка на дело скопирована.');
  } catch (_) {
    downloadTextFile(`EPSOK-link-${caseId}.txt`, text);
    showToast('Ссылка сохранена в файл.');
  }
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
  const sessionPersona = session.personaId && demoPersonas[session.personaId] ? session.personaId : null;
  if (sessionPersona && canUsePersona(sessionPersona, session.username)) {
    if (!session.personaExplicit && sessionPersona === 'INV_MVD' && defaultPersonaId !== 'INV_MVD') {
      activePersonaId = defaultPersonaId;
      await saveSession(session.username, remember, activePersonaId);
    } else {
      activePersonaId = sessionPersona;
    }
  } else {
    activePersonaId = defaultPersonaId;
    await saveSession(session.username, remember, activePersonaId);
    if (sessionPersona && sessionPersona !== defaultPersonaId) {
      pushAuditEntry('Отклонена роль в сессии', sessionPersona, 'ПОЛ-008');
    }
  }
  return true;
}

function syncAuthShellVisibility(loggedIn) {
  document.documentElement.dataset.auth = loggedIn ? 'app' : 'login';
}

function showLoginScreen() {
  stopSessionGuard();
  syncAuthShellVisibility(false);
  document.getElementById('login-screen')?.classList.remove('hidden');
  document.getElementById('app-root')?.classList.add('hidden');
  document.getElementById('login-error')?.classList.add('hidden');
  syncLoginSecureHint();
}

function syncLoginSecureHint() {
  const hint = document.getElementById('login-secure-hint');
  if (!hint || typeof EpsokSecurity === 'undefined' || !EpsokSecurity.hasWebCrypto) return;
  hint.classList.toggle('hidden', EpsokSecurity.hasWebCrypto());
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
    initModalDismiss();
    initSidebar();
    updateSecurityStrip();
    await loadHrState();
    await loadEvidencePackages();
    loadCasesRegistryOverrides();
    bootstrapAllCaseGraphs();
    try {
      await ensureCorpMailReady();
    } catch (mailErr) {
      console.error(mailErr);
      await resetCorpMailState();
      showToast('Почтовый ящик восстановлен из демо-шаблона');
    }
    updateMailSidebarBadge();
    updateRequestsSidebarBadge();
    clearSavedActiveView();
    showView('dashboard');
    startSessionGuard();
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

function logout(options = {}) {
  if (!options?.skipAudit && currentUser) {
    pushAuditEntry('Выход', `Сессия · ${currentUser.username}`, 'ПОЛ-005');
  }
  clearSession();
  currentUser = null;
  activePersonaId = 'INV_MVD';
  graphView.deactivate();
  document.getElementById('login-form')?.reset();
  document.getElementById('login-remember').checked = false;
  showLoginScreen();
}

const SESSION_IDLE_LOCK_MS = 15 * 60 * 1000;
const SESSION_IDLE_WARN_MS = 60 * 1000;
let sessionIdleTimer = null;
let sessionWarnTimer = null;
let sessionIdleCountdown = null;
let sessionActivityDeadline = 0;
let sessionActivityTicker = null;
let sessionGuardBound = false;

function isAppLoggedIn() {
  return document.documentElement.dataset.auth === 'app' && !!currentUser;
}

function hideIdleWarning() {
  if (sessionIdleCountdown) {
    clearInterval(sessionIdleCountdown);
    sessionIdleCountdown = null;
  }
  document.getElementById('idle-warning')?.classList.add('hidden');
}

function formatSessionIdleRemaining(ms) {
  if (ms <= 0) return 'блокировка…';
  const totalMin = Math.ceil(ms / 60000);
  if (totalMin >= 60) {
    const h = Math.floor(totalMin / 60);
    const m = totalMin % 60;
    return m ? `${h} ч ${m} мин` : `${h} ч`;
  }
  return `${totalMin} мин`;
}

function updateSessionActivityPill() {
  const pill = document.getElementById('session-activity-pill');
  if (!pill) return;
  if (!isAppLoggedIn()) {
    pill.classList.add('hidden');
    pill.classList.remove('session-warn');
    return;
  }
  const left = sessionActivityDeadline - Date.now();
  pill.classList.remove('hidden');
  pill.textContent = `⏱ ${formatSessionIdleRemaining(left)}`;
  pill.classList.toggle('session-warn', left > 0 && left <= SESSION_IDLE_WARN_MS * 2);
}

function showIdleWarning() {
  if (!isAppLoggedIn()) return;
  const overlay = document.getElementById('idle-warning');
  const countdownEl = document.getElementById('idle-warning-countdown');
  if (!overlay) return;
  overlay.classList.remove('hidden');
  let secLeft = Math.ceil(SESSION_IDLE_WARN_MS / 1000);
  if (countdownEl) countdownEl.textContent = String(secLeft);
  if (sessionIdleCountdown) clearInterval(sessionIdleCountdown);
  sessionIdleCountdown = setInterval(() => {
    secLeft -= 1;
    if (countdownEl) countdownEl.textContent = String(Math.max(secLeft, 0));
    updateSessionActivityPill();
    if (secLeft <= 0) {
      clearInterval(sessionIdleCountdown);
      sessionIdleCountdown = null;
      lockNow('idle');
    }
  }, 1000);
}

function resetSessionIdleTimers() {
  if (sessionIdleTimer) clearTimeout(sessionIdleTimer);
  if (sessionWarnTimer) clearTimeout(sessionWarnTimer);
  sessionIdleTimer = null;
  sessionWarnTimer = null;
  hideIdleWarning();
  if (!isAppLoggedIn()) return;
  sessionActivityDeadline = Date.now() + SESSION_IDLE_LOCK_MS;
  updateSessionActivityPill();
  sessionWarnTimer = setTimeout(showIdleWarning, SESSION_IDLE_LOCK_MS - SESSION_IDLE_WARN_MS);
  sessionIdleTimer = setTimeout(() => lockNow('idle'), SESSION_IDLE_LOCK_MS);
}

function stopSessionGuard() {
  if (sessionIdleTimer) clearTimeout(sessionIdleTimer);
  if (sessionWarnTimer) clearTimeout(sessionWarnTimer);
  if (sessionActivityTicker) clearInterval(sessionActivityTicker);
  sessionIdleTimer = null;
  sessionWarnTimer = null;
  sessionActivityTicker = null;
  sessionActivityDeadline = 0;
  hideIdleWarning();
  updateSessionActivityPill();
}

function dismissIdleWarning() {
  hideIdleWarning();
  resetSessionIdleTimers();
  showToast('Сессия продлена.');
}

function startSessionGuard() {
  if (!isAppLoggedIn()) return;
  if (!sessionGuardBound) {
    sessionGuardBound = true;
    const bump = () => {
      if (!isAppLoggedIn()) return;
      resetSessionIdleTimers();
    };
    ['pointerdown', 'keydown', 'scroll', 'touchstart'].forEach((ev) => {
      document.addEventListener(ev, bump, { passive: true });
    });
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'visible') bump();
    });
    document.addEventListener('keydown', (e) => {
      if (!isAppLoggedIn()) return;
      if (e.ctrlKey && e.shiftKey && e.key.toLowerCase() === 'l') {
        e.preventDefault();
        lockNow('manual');
      }
    });
  }
  resetSessionIdleTimers();
  if (!sessionActivityTicker) {
    sessionActivityTicker = setInterval(updateSessionActivityPill, 30000);
  }
}

// Локальная быстрая блокировка интерфейса: очищает сессию и возвращает экран входа.
function lockNow(reason = 'manual') {
  stopSessionGuard();
  if (currentUser) {
    const action = reason === 'idle' ? 'Автоблокировка' : 'Блокировка';
    pushAuditEntry(action, `Сессия · ${currentUser.username}`, 'ПОЛ-005');
  }
  try {
    logout({ skipAudit: true });
    const msg = reason === 'idle'
      ? 'Сессия заблокирована из‑за неактивности. Войдите снова.'
      : 'Сессия заблокирована. Войдите снова.';
    showToast(msg);
  } catch (_) {
    try { showLoginScreen(); } catch { /* noop */ }
  }
}

function showUtilView(viewId) {
  showView(viewId);
  if (viewId === 'support') {
    prefillSupportContact();
    updateSupportSlaHint();
    renderSupportTicketHistory();
  }
}

const SUPPORT_SLA_LABELS = {
  critical: '1 ч',
  high: '4 ч',
  normal: '1 раб. день'
};

function updateSupportSlaHint() {
  const pri = document.getElementById('support-priority')?.value || 'normal';
  const el = document.getElementById('support-sla-hint');
  if (el) el.textContent = `Ожидаемое время реакции: ${SUPPORT_SLA_LABELS[pri] || '—'}`;
}

function prefillSupportContact() {
  const field = document.getElementById('support-contact');
  if (!field || field.value.trim()) return;
  const user = currentUser?.username;
  if (user) field.value = `${user}@epsok.gov.ru`;
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

// Ручной импорт текстов статей (только оригинальные краткие описания — не копировать КонсультантПлюс).
// Ключ: `${id_акта}:${номер_статьи}` — см. LEGAL_KEY_ARTICLES и id в LEGAL_BASE.
const LEGAL_ARTICLE_TEXTS = {
  'upk:144': 'Возбуждение дела — после проверки сообщения о преступлении. В ЕПСОК создаётся карточка, назначается рабочая группа, фиксируется основание доступа (ПОЛ-001).',
  'upk:186': 'Истребование сведений о соединениях и сообщениях — по постановлению следователя. В ЕПСОК тип запроса CDR, обязательная ссылка на постановление, ответ прикрепляется к делу и графу.',
  'upk:109': 'Сроки содержания под стражей — контроль в Deadline Engine, уведомления при приближении истечения.',
  'fz152:6': 'Законные основания обработки ПДн. Каждый просмотр карточки и межвед-запрос в ЕПСОК должен иметь процессуальное или договорное основание.',
  'fz152:18': 'Обязанности оператора: меры защиты, уведомление РКН, учёт обращений субъектов ПДн.',
  'uk:137': 'Нарушение неприкосновенности частной жизни — риск при массовом просмотре без основания (связка с ПОЛ-005 и журналом аудита).',
  'uk:272': 'Неправомерный доступ к компьютерной информации — применимо к попыткам обхода RBAC и экспорту без ПОЛ-004.'
};

const LEGAL_KEY_ARTICLES = {
  upk: [
    { num: '144', title: 'Поводы и основания возбуждения', summary: 'Проверка сообщения, решение о возбуждении или отказе, уведомление заявителя.', epsok: 'Регистрация дела · рабочая группа · старт сроков' },
    { num: '162', title: 'Сроки дознания', summary: 'Общий и продлённый срок дознания, основания продления.', epsok: 'Deadline Engine · эскалация руководителю' },
    { num: '186', title: 'Сведения о соединениях', summary: 'Истребование у операторов связи данных о входящих/исходящих вызовах и сообщениях.', epsok: 'Запросы CDR · постановление · ответ в дело' },
    { num: '109', title: 'Сроки содержания под стражей', summary: 'Два, четыре и шесть месяцев — в зависимости от стадии и тяжести.', epsok: 'Контроль сроков · связка с ФСИН' }
  ],
  uk: [
    { num: '137', title: 'Нарушение неприкосновенности частной жизни', summary: 'Незаконный сбор и распространение сведений о частной жизни.', epsok: 'Аудит просмотров · ПОЛ-005' },
    { num: '272', title: 'Неправомерный доступ к информации', summary: 'Доступ к охраняемой компьютерной информации с нарушением правил.', epsok: 'RBAC · журнал НЗАП' },
    { num: '274.1', title: 'Незаконное воздействие на КИИ', summary: 'Блокирование, уничтожение или модификация информации КИИ.', epsok: 'Контур ЦОД · 187-ФЗ' }
  ],
  koap: [
    { num: '13.11', title: 'Нарушение порядка обработки ПДн', summary: 'Административная ответственность оператора ПДн.', epsok: 'Санкции при нарушении POL-005' },
    { num: '13.14', title: 'Незаконный оборот ПДн', summary: 'Передача или распространение без согласия субъекта.', epsok: 'Контроль экспорта · ПОЛ-004' }
  ],
  fz3: [
    { num: '1', title: 'Назначение полиции', summary: 'Защита прав, безопасность, профилактика, раскрытие, дознание.', epsok: 'Контур МВД · ГИАЦ · КУСП' },
    { num: '13', title: 'Проверка сообщений', summary: 'Проверка по заявлениям и материалам, сроки и полномочия.', epsok: 'Дознание · сроки УПК' }
  ],
  fz403: [
    { num: '1', title: 'Статус и задачи СК', summary: 'Следственный комитет — самостоятельный федеральный орган.', epsok: 'Подследственность SK_*' },
    { num: '12', title: 'Полномочия следователя СК', summary: 'Расследование, запросы, процессуальные решения.', epsok: 'Карточка дела · экспертизы' }
  ],
  fz152: [
    { num: '6', title: 'Условия обработки ПДн', summary: 'Согласие, договор, закон, жизненно важные интересы и др.', epsok: 'Основание каждого запроса' },
    { num: '10', title: 'Специальные категории', summary: 'Усиленные требования к биометрии, здоровью, судимости.', epsok: 'Классификация ИСПДн' },
    { num: '18', title: 'Обязанности оператора', summary: 'Меры защиты, локализация, уведомления, ответы субъектам.', epsok: 'Шифрование · POL-005' }
  ],
  fz144: [
    { num: '1', title: 'Основы ОРД', summary: 'Цели, принципы, правовая основа оперативно-розыскной деятельности.', epsok: 'Оперативный контур · номер ОРД' },
    { num: '7', title: 'Оперативно-розыскные мероприятия', summary: 'Перечень ОРМ, включая наблюдение и контроль связи.', epsok: '«Горизонт» (огран.) · разграничение с следствием' }
  ],
  fz2202: [
    { num: '21', title: 'Надзор за исполнением законов', summary: 'Прокурор вправе требовать материалы и давать поручения.', epsok: 'Надзорный доступ · POL-002' },
    { num: '57', title: 'Участие в уголовном судопроизводстве', summary: 'Согласование, отмена решений, поддержание обвинения.', epsok: 'Serendipity · POL-007' }
  ],
  fz63: [
    { num: '5', title: 'Виды электронной подписи', summary: 'Простая, усиленная неквалифицированная и квалифицированная ЭП.', epsok: 'ГОСТ-токен · корпоративная почта' },
    { num: '6', title: 'Юридическая сила ЭП', summary: 'Равнозначность собственноручной подписи при соблюдении требований.', epsok: 'Подписание запросов и пакетов' }
  ]
};

function legalPravoSearchUrl(query) {
  return 'https://pravo.gov.ru/search/?query=' + encodeURIComponent(query);
}

function legalConsultantSearchUrl(query) {
  return 'https://www.consultant.ru/search/?q=' + encodeURIComponent(query);
}

function getLegalDocById(id) {
  return LEGAL_BASE.find(l => l.id === id);
}

function attachLegalKeyArticles() {
  LEGAL_BASE.forEach(l => {
    if (LEGAL_KEY_ARTICLES[l.id]) l.keyArticles = LEGAL_KEY_ARTICLES[l.id];
    if (!l.officialQuery) l.officialQuery = l.code + ' ' + (l.title.split(' ').slice(-3).join(' ') || '');
  });
}

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
  { id: 'fz73', code: '73-ФЗ', docType: 'federal_law', category: 'judiciary', title: 'О государственной судебно-экспертной деятельности', articles: 'ст. 1–20', summary: 'Назначение и проведение судебных экспертиз.', epsok: 'SK_EXPERTISE · сроки экспертиз в Deadline Engine', agencies: ['SK', 'COURT'], tags: ['экспертиза'] },
  { id: 'fz63', code: '63-ФЗ', docType: 'federal_law', category: 'personal_data', title: 'Об электронной подписи', articles: 'ст. 1–18', summary: 'Виды ЭП, юридическая сила, удостоверяющие центры, требования к средствам подписи.', epsok: 'ГОСТ-токен · подписание запросов · корпоративная почта · ЕСИА', agencies: ['MINDIG', 'ALL'], tags: ['ЭП', 'ЕСИА', 'подпись'] },
  { id: 'fz323', code: '323-ФЗ', docType: 'federal_law', category: 'criminal_procedure', title: 'О неприкосновенности частной жизни', articles: 'ст. 1–24', summary: 'Ограничения сбора и использования сведений о частной жизни, в т.ч. при оперативно-розыскной деятельности.', epsok: 'Разграничение следствия и ОРД · основания прослушивания · аудит', agencies: ['MVD', 'FSB', 'ALL'], tags: ['ПДн', 'ОРД', 'прослушивание'] },
  { id: 'fz176', code: '176-ФЗ', docType: 'federal_law', category: 'interagency', title: 'О связи', articles: 'ст. 53, 64', summary: 'Обязанности операторов связи по оказанию услуг правоохранительным органам в предусмотренных законом случаях.', epsok: 'Запросы CDR · ст. 186 УПК · SLA операторов', agencies: ['MVD', 'FSB'], tags: ['связь', 'CDR', 'операторы'] },
  { id: 'fz326', code: '326-ФЗ', docType: 'federal_law', category: 'agency_powers', title: 'О государственной регистрации населения', articles: 'ст. 1–22', summary: 'Паспорта, регистрация по месту жительства, ЕСИА и сведения о гражданах.', epsok: 'MVD_PASSPORT · идентификация лиц · запросы ГИАЦ', agencies: ['MVD'], tags: ['паспорт', 'ЕСИА', 'ГИАЦ'] },
  { id: 'fz167', code: '167-ФЗ', docType: 'federal_law', category: 'interagency', title: 'О СМЭВ', articles: 'ст. 1–15', summary: 'Единая система межведомственного электронного взаимодействия, шлюз и регламенты обмена.', epsok: 'Модуль «Запросы» · адаптеры ведомств · статусы SLA', agencies: ['MINDIG', 'ALL'], tags: ['СМЭВ', 'межвед'] }
];

attachLegalKeyArticles();

// --- Мониторинг законодательства (демо-симуляция pravo.gov.ru) ---

const LEGISLATION_SYNC_STORAGE = 'epsok-legislation-sync';
const LEGISLATION_CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000;
let legislationMonitorTimer = null;
let legislationSyncStateCache = null;

const LEGISLATION_STAGED_UPDATES = {
  upk: {
    revisionDate: '2026-03-15',
    version: 'ред. 15.03.2026',
    note: 'Уточнён порядок запроса сведений о соединениях (ст. 186 УПК РФ)'
  },
  fz152: {
    revisionDate: '2026-05-20',
    version: 'ред. 20.05.2026',
    note: 'Изменения в правах субъекта ПДн (ст. 18–19 152-ФЗ)'
  }
};

const LEGISLATION_REGISTRY_OVERRIDES = {
  fz187: { revisionDate: '2026-04-28', version: 'ред. 28.04.2026' },
  fz149: { revisionDate: '2026-02-14', version: 'ред. 14.02.2026' },
  nk: { revisionDate: '2025-12-01', version: 'ред. 01.12.2025' },
  fz115: { revisionDate: '2025-11-08', version: 'ред. 08.11.2025' }
};

const LEGISLATION_INITIAL_LOCAL_OVERRIDES = {
  upk: { revisionDate: '2025-08-01', version: 'ред. 01.08.2025' },
  fz152: { revisionDate: '2025-06-10', version: 'ред. 10.06.2025' }
};

const LEGISLATION_SEED_CHANGELOG = [
  {
    at: '2026-05-12T08:00:00.000Z',
    lawId: 'fz187',
    code: '187-ФЗ',
    title: 'О безопасности критической информационной инфраструктуры',
    revisionDate: '2026-04-28',
    note: 'Уточнены требования к объектам КИИ и мерам защиты'
  },
  {
    at: '2026-03-01T10:30:00.000Z',
    lawId: 'fz149',
    code: '149-ФЗ',
    title: 'Об информации, информационных технологиях и защите информации',
    revisionDate: '2026-02-14',
    note: 'Актуализированы требования к государственным информационным системам'
  },
  {
    at: '2025-12-15T14:00:00.000Z',
    lawId: 'nk',
    code: 'НК РФ',
    title: 'Налоговый кодекс РФ',
    revisionDate: '2025-12-01',
    note: 'Уточнён порядок предоставления сведений по ст. 93 и 102'
  }
];

function revisionHash(lawId, revisionDate) {
  let h = 0;
  const s = `${lawId}|${revisionDate}`;
  for (let i = 0; i < s.length; i++) h = ((h << 5) - h) + s.charCodeAt(i);
  return Math.abs(h).toString(16).padStart(8, '0').slice(0, 8);
}

function compareRevisionDate(a, b) {
  const ta = Date.parse(a || 0);
  const tb = Date.parse(b || 0);
  if (ta === tb) return 0;
  return ta > tb ? 1 : -1;
}

function formatLegislationDateRu(iso) {
  if (!iso) return '—';
  const m = String(iso).match(/^(\d{4})-(\d{2})-(\d{2})/);
  if (m) return `${m[3]}.${m[2]}.${m[1]}`;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return `${String(d.getDate()).padStart(2, '0')}.${String(d.getMonth() + 1).padStart(2, '0')}.${d.getFullYear()}`;
}

function formatLegislationDateTimeRu(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return formatLegislationDateRu(iso);
  const date = formatLegislationDateRu(iso);
  const hh = String(d.getHours()).padStart(2, '0');
  const min = String(d.getMinutes()).padStart(2, '0');
  return `${date} ${hh}:${min}`;
}

function defaultRevisionForLaw(law, index) {
  const base = new Date('2024-03-01T00:00:00.000Z');
  base.setUTCMonth(base.getUTCMonth() + (index % 20));
  const revisionDate = base.toISOString().slice(0, 10);
  return {
    revisionDate,
    version: `ред. ${formatLegislationDateRu(revisionDate)}`,
    hash: revisionHash(law.id, revisionDate)
  };
}

function buildLegislationDocEntry(law, index, overrides) {
  const base = defaultRevisionForLaw(law, index);
  const merged = { ...base, ...(overrides || {}) };
  return {
    revisionDate: merged.revisionDate,
    version: merged.version || `ред. ${formatLegislationDateRu(merged.revisionDate)}`,
    hash: revisionHash(law.id, merged.revisionDate),
    lastUpdatedAt: `${merged.revisionDate}T09:00:00.000Z`,
    lastCheckedAt: '2026-06-14T06:00:00.000Z'
  };
}

function buildDefaultLegislationSyncState() {
  const documents = {};
  LEGAL_BASE.forEach((law, index) => {
    const overrides = LEGISLATION_INITIAL_LOCAL_OVERRIDES[law.id]
      || LEGISLATION_REGISTRY_OVERRIDES[law.id]
      || null;
    documents[law.id] = buildLegislationDocEntry(law, index, overrides);
  });
  return {
    version: 1,
    lastSyncAt: '2026-06-14T06:00:00.000Z',
    lastCheckedAt: '2026-06-14T06:00:00.000Z',
    documents,
    changelog: LEGISLATION_SEED_CHANGELOG.slice(),
    appliedStaged: []
  };
}

function loadLegislationSyncState() {
  if (legislationSyncStateCache) return legislationSyncStateCache;
  try {
    const raw = localStorage.getItem(LEGISLATION_SYNC_STORAGE);
    if (raw) {
      const parsed = JSON.parse(raw);
      if (parsed?.documents) {
        LEGAL_BASE.forEach((law, index) => {
          if (!parsed.documents[law.id]) {
            parsed.documents[law.id] = buildLegislationDocEntry(law, index);
          }
        });
        parsed.changelog = Array.isArray(parsed.changelog) ? parsed.changelog : [];
        parsed.appliedStaged = Array.isArray(parsed.appliedStaged) ? parsed.appliedStaged : [];
        legislationSyncStateCache = parsed;
        return parsed;
      }
    }
  } catch {
    /* fall through */
  }
  legislationSyncStateCache = buildDefaultLegislationSyncState();
  saveLegislationSyncState(legislationSyncStateCache);
  return legislationSyncStateCache;
}

function saveLegislationSyncState(state) {
  legislationSyncStateCache = state;
  localStorage.setItem(LEGISLATION_SYNC_STORAGE, JSON.stringify(state));
}

function getLawSyncMeta(lawId) {
  const state = loadLegislationSyncState();
  return state.documents?.[lawId] || null;
}

function getSimulatedRemoteRevision(lawId, state) {
  const staged = LEGISLATION_STAGED_UPDATES[lawId];
  if (staged && !(state.appliedStaged || []).includes(lawId)) {
    return {
      revisionDate: staged.revisionDate,
      version: staged.version,
      hash: revisionHash(lawId, staged.revisionDate),
      note: staged.note,
      staged: true
    };
  }
  const registry = LEGISLATION_REGISTRY_OVERRIDES[lawId];
  const local = state.documents?.[lawId];
  if (registry) {
    return {
      revisionDate: registry.revisionDate,
      version: registry.version,
      hash: revisionHash(lawId, registry.revisionDate),
      note: 'Актуальная редакция в официальном реестре (демо)'
    };
  }
  return {
    revisionDate: local?.revisionDate || '2024-01-01',
    version: local?.version || 'ред. 01.01.2024',
    hash: local?.hash || revisionHash(lawId, '2024-01-01')
  };
}

const LEGISLATION_IMPACT_STORAGE = 'epsok-legislation-impact';

function computeLegislationImpactedCases(updated) {
  const hasUpk = (updated || []).some(u => u.lawId === 'upk' || u.code === 'УПК РФ');
  if (!hasUpk) return [];
  return casesRegistry.filter(c => c.daysLeft != null && c.daysLeft <= 14 && isOpenCase(c));
}

function saveLegislationImpact(cases, updated) {
  const payload = {
    at: new Date().toISOString(),
    updated: (updated || []).map(u => ({ lawId: u.lawId, code: u.code, note: u.note })),
    cases: cases.map(c => ({ id: c.id, daysLeft: c.daysLeft, article: c.article }))
  };
  try { localStorage.setItem(LEGISLATION_IMPACT_STORAGE, JSON.stringify(payload)); } catch (_) { /* demo */ }
  return payload;
}

function loadLegislationImpact() {
  try { return JSON.parse(localStorage.getItem(LEGISLATION_IMPACT_STORAGE) || 'null'); }
  catch { return null; }
}

function dismissLegislationImpactBanner() {
  try { localStorage.removeItem(LEGISLATION_IMPACT_STORAGE); } catch (_) { /* demo */ }
  document.getElementById('reg-laws-impact-banner')?.classList.add('hidden');
  document.getElementById('prosecutor-legislation-impact')?.classList.add('hidden');
  if (document.getElementById('view-dashboard')?.classList.contains('active')) renderDashboard();
}

function renderLegislationImpactBannerHtml(impact, opts = {}) {
  if (!impact?.cases?.length) return '';
  const compact = opts.compact;
  const cases = impact.cases.slice(0, compact ? 3 : 8);
  const caseList = cases.map(c =>
    `<li><button type="button" class="case-link" onclick="openCase('${c.id}')">${escapeHtml(c.id)}</button>`
    + ` · ${escapeHtml((c.article || '').replace(' УК РФ', ''))} · <strong>${c.daysLeft} дн.</strong></li>`
  ).join('');
  const more = impact.cases.length > cases.length
    ? `<p class="muted">и ещё ${impact.cases.length - cases.length} дел(а)…</p>` : '';
  const laws = (impact.updated || []).filter(u => u.lawId === 'upk' || u.code === 'УПК РФ')
    .map(u => escapeHtml(u.code)).join(', ') || 'УПК РФ';
  return `<div class="legislation-impact-banner-inner">
    <p><strong>Изменения ${laws}</strong> · затронуты активные дела с сроком ≤14 дн. (${impact.cases.length})
      <button type="button" class="btn-sm legislation-impact-export-btn" onclick="downloadLegislationImpactTxt()">Отчёт (TXT)</button></p>
    <ul class="legislation-impact-cases">${caseList}</ul>
    ${more}
    <button type="button" class="reg-laws-sync-banner-close" onclick="dismissLegislationImpactBanner()" aria-label="Закрыть">×</button>
  </div>`;
}

function refreshLegislationImpactBanners() {
  const impact = loadLegislationImpact();
  const regBanner = document.getElementById('reg-laws-impact-banner');
  if (regBanner) {
    if (impact?.cases?.length) {
      regBanner.innerHTML = renderLegislationImpactBannerHtml(impact);
      regBanner.classList.remove('hidden');
    } else {
      regBanner.classList.add('hidden');
    }
  }
}

function showLegislationSyncBanner(updated) {
  const banner = document.getElementById('reg-laws-sync-banner');
  if (!banner || !updated?.length) return;
  const list = updated.map(u =>
    `<li><strong>${escapeHtml(u.code)}</strong> — ${escapeHtml(u.note || 'обновлена редакция')}</li>`
  ).join('');
  banner.innerHTML = `<div class="reg-laws-sync-banner-inner">
    <p><strong>Обнаружены обновления законодательства</strong> (${updated.length})</p>
    <ul>${list}</ul>
    <button type="button" class="reg-laws-sync-banner-close" onclick="dismissLegislationSyncBanner()" aria-label="Закрыть">×</button>
  </div>`;
  banner.classList.remove('hidden');
  refreshLegislationImpactBanners();
}

function dismissLegislationSyncBanner() {
  document.getElementById('reg-laws-sync-banner')?.classList.add('hidden');
}

function renderLegislationSyncUi() {
  const state = loadLegislationSyncState();
  const statusEl = document.getElementById('reg-laws-sync-status');
  const btn = document.getElementById('reg-laws-sync-btn');
  const changelogEl = document.getElementById('reg-laws-changelog');

  if (statusEl) {
    const syncAt = formatLegislationDateTimeRu(state.lastSyncAt);
    const checkedAt = formatLegislationDateTimeRu(state.lastCheckedAt);
    statusEl.innerHTML = `Последняя синхронизация: <strong>${escapeHtml(syncAt)}</strong>`
      + ` · проверено: ${escapeHtml(checkedAt)}`
      + ` <span class="reg-laws-sync-source muted">источник: pravo.gov.ru (демо)</span>`;
  }
  if (btn) {
    btn.disabled = !!state.syncInProgress;
    btn.textContent = state.syncInProgress ? 'Проверка…' : 'Проверить обновления';
  }
  if (changelogEl) {
    const items = (state.changelog || []).slice(0, 12);
    changelogEl.innerHTML = items.length
      ? items.map(entry => {
        const when = formatLegislationDateTimeRu(entry.at);
        const rev = formatLegislationDateRu(entry.revisionDate);
        return `<li><time datetime="${escapeHtml(entry.at || '')}">${escapeHtml(when)}</time>`
          + ` · <strong>${escapeHtml(entry.code)}</strong> — ${escapeHtml(entry.title)}`
          + ` <span class="muted">(ред. ${escapeHtml(rev)})</span>`
          + `${entry.note ? `<br><span class="reg-laws-changelog-note">${escapeHtml(entry.note)}</span>` : ''}`
          + `</li>`;
      }).join('')
      : '<li class="muted">Обновлений пока не зафиксировано</li>';
  }
}

async function runLegislationSync(options = {}) {
  const { manual = false, silent = false } = options;
  const state = loadLegislationSyncState();
  if (state.syncInProgress) return { updated: [] };

  state.syncInProgress = true;
  saveLegislationSyncState(state);
  renderLegislationSyncUi();

  if (manual) await new Promise(resolve => setTimeout(resolve, 700));

  const now = new Date().toISOString();
  const updated = [];

  LEGAL_BASE.forEach(law => {
    const doc = { ...(state.documents[law.id] || buildLegislationDocEntry(law, 0)) };
    const remote = getSimulatedRemoteRevision(law.id, state);
    doc.lastCheckedAt = now;

    if (compareRevisionDate(remote.revisionDate, doc.revisionDate) > 0) {
      doc.revisionDate = remote.revisionDate;
      doc.version = remote.version;
      doc.hash = remote.hash;
      doc.lastUpdatedAt = now;
      updated.push({
        lawId: law.id,
        code: law.code,
        title: law.title,
        revisionDate: remote.revisionDate,
        note: remote.note || 'Обновлена редакция на официальном портале (демо)'
      });
      if (remote.staged) {
        state.appliedStaged = state.appliedStaged || [];
        if (!state.appliedStaged.includes(law.id)) state.appliedStaged.push(law.id);
      }
    }
    state.documents[law.id] = doc;
  });

  if (updated.length) {
    const entries = updated.map(u => ({ at: now, ...u }));
    state.changelog = entries.concat(state.changelog || []).slice(0, 30);
    state.lastSyncAt = now;
  } else if (manual) {
    state.lastSyncAt = now;
  }

  state.lastCheckedAt = now;
  state.syncInProgress = false;
  saveLegislationSyncState(state);

  if (!silent) {
    if (updated.length) {
      showToast(`Законодательство: обновлено ${updated.length} акт(ов)`);
      showLegislationSyncBanner(updated);
    } else if (manual) {
      showToast('Проверка завершена · новых редакций не найдено');
    }
  } else if (updated.length) {
    showLegislationSyncBanner(updated);
    showToast(`Автопроверка: обновлено ${updated.length} акт(ов) законодательства`);
  }

  if (updated.length) {
    const impacted = computeLegislationImpactedCases(updated);
    if (impacted.length) {
      saveLegislationImpact(impacted, updated);
      if (!silent || manual) {
        showToast(`НПА: проверьте сроки по ${impacted.length} дел(ам) (изменения УПК)`);
      }
    }
  }
  refreshLegislationImpactBanners();
  if (document.getElementById('view-dashboard')?.classList.contains('active')
    && getActivePersona()?.dashboardMode === 'prosecutor') {
    renderProsecutorDashboard(getActivePersona());
  }

  renderLegislationSyncUi();
  if (document.getElementById('reg-pane-laws')?.classList.contains('active')) renderLegalBase();
  return { updated };
}

function runLegislationSyncManual() {
  return runLegislationSync({ manual: true });
}

function maybeAutoCheckLegislation(options = {}) {
  const state = loadLegislationSyncState();
  const last = state.lastCheckedAt ? new Date(state.lastCheckedAt).getTime() : 0;
  if (Date.now() - last >= LEGISLATION_CHECK_INTERVAL_MS) {
    return runLegislationSync({ silent: options.silent !== false });
  }
  renderLegislationSyncUi();
  return Promise.resolve({ updated: [] });
}

function initLegislationMonitor() {
  loadLegislationSyncState();
  renderLegislationSyncUi();
  refreshLegislationImpactBanners();
  void maybeAutoCheckLegislation({ silent: true });
  if (legislationMonitorTimer) clearInterval(legislationMonitorTimer);
  legislationMonitorTimer = setInterval(() => {
    void maybeAutoCheckLegislation({ silent: true });
  }, LEGISLATION_CHECK_INTERVAL_MS);
}

async function adminSyncLegislation() {
  await runLegislationSync({ manual: true });
}

const ARTICLE_EXPL_STORAGE = 'epsok-article-explanations';

const DEFAULT_ARTICLE_EXPLANATIONS = {
  'upk|7': 'Задачи уголовного судопроизводства: защита прав и свобод, привлечение виновных, защита невиновных.',
  'upk|7-21': 'Общие положения УПК: принципы, участники процесса, язык, обязанности дознавателя и следователя.',
  'upk|37-41': 'Право на защиту: защитник, представитель потерпевшего, порядок участия в процессе.',
  'upk|75': 'Недопустимые доказательства: полученные с нарушением закона не могут использоваться в суде.',
  'upk|89': 'Передача материалов проверки или дела по подследственности другому органу.',
  'upk|109': 'Сроки задержания: 48 часов, до 72 часов в исключительных случаях; порядок содержания под стражей.',
  'upk|144-186': 'Доследственная проверка, возбуждение и прекращение дела, предварительное следствие.',
  'upk|186': 'Получение сведений о соединениях между абонентами (детализация связи, CDR).',
  'upk|195-207': 'Назначение и проведение судебной экспертизы, права и обязанности эксперта.',
  'upk|217': 'Ознакомление участников процесса с материалами уголовного дела перед окончанием следствия.',
  'upk|223': 'Сроки дознания: 30 суток с возможностью продления ещё на 30 суток.',
  'upk|226': 'Продление сроков предварительного следствия прокурором или судом.',
  'upk|151': 'Подследственность: распределение дел между органами предварительного расследования.',
  'upk|162': 'Сроки предварительного следствия: 2 месяца с возможностью продления.',
  'upk|208': 'Приостановление предварительного следствия (например, при розыске подозреваемого).',
  'uk|137': 'Уголовная ответственность за нарушение неприкосновенности частной жизни.',
  'uk|272': 'Неправомерный доступ к охраняемой компьютерной информации.',
  'uk|274.1': 'Создание и распространение вредоносных компьютерных программ.',
  'koap|13.11': 'Административная ответственность за нарушение законодательства о персональных данных.',
  'koap|13.14': 'Незаконные сбор и распространение сведений о частной жизни.',
  'fz152|6': 'Условия обработки персональных данных: согласие, договор, закон и др.',
  'fz152|10': 'Запрет обработки специальных категорий ПДн (раса, здоровье, судимость и т.д.).',
  'fz152|18-19': 'Права субъекта ПДн и обязанности оператора по обеспечению этих прав.',
  'nk|93': 'Предоставление налоговым органом сведений о счетах налогоплательщика по запросу следствия.',
  'nk|102': 'Предоставление справок о доходах физических лиц (2-НДФЛ) по запросу следствия.',
  'fz2202|57': 'Полномочия прокурора в уголовном судопроизводстве и надзор за соблюдением законов.',
  'fz144|1-18': 'Правовые основы оперативно-розыскной деятельности и виды ОРМ.',
  'fz115|7': 'Обязанности организаций по идентификации клиентов и фиксации операций (ПОД/ФТ).',
  'fz115|8': 'Передача сведений о подозрительных операциях в Росфинмониторинг.',
  'fz63|5': 'Виды электронной подписи: простая, усиленная неквалифицированная и квалифицированная.',
  'fz63|6': 'Юридическая сила ЭП при соблюдении требований закона — равнозначна собственноручной подписи.',
  'fz323|1-24': 'Ограничения на сбор и использование сведений о частной жизни граждан.',
  'fz176|53': 'Обязанности операторов связи по оказанию услуг в случаях, предусмотренных федеральными законами.',
  'fz176|64': 'Взаимодействие операторов связи с правоохранительными органами при исполнении запросов.',
  'fz326|1-22': 'Паспорта, регистрация, ЕСИА — идентификация граждан в межведомственных запросах.',
  'fz167|1-15': 'СМЭВ: единый шлюз межведомственного электронного взаимодействия и регламенты обмена.'
};

let articleExplanationCtx = null;

function normalizeArticleKey(prefix, ref) {
  const p = (prefix || '').trim().toLowerCase();
  const r = ref.trim().replace(/\s+/g, '').replace(/–/g, '-');
  if (p.startsWith('гл')) return `гл.${r}`;
  if (p.startsWith('ч')) return `ч.${r}`;
  return r;
}

function loadArticleExplanations() {
  try {
    return JSON.parse(localStorage.getItem(ARTICLE_EXPL_STORAGE) || '{}');
  } catch {
    return {};
  }
}

function articleExplStorageKey(lawId, articleKey) {
  return `${lawId}|${articleKey}`;
}

function renderLegalEpsokHtml(epsok) {
  if (!canViewSystemInternals() || !epsok) return '';
  return `<p class="reg-law-epsok"><span class="reg-law-epsok-label">ЕПСОК:</span> ${escapeHtml(epsok)}</p>`;
}

function getDefaultArticleExplanation(law, articleKey, p = getActivePersona()) {
  const internals = canViewSystemInternals(p);
  const key = articleExplStorageKey(law.id, articleKey);
  if (internals && DEFAULT_ARTICLE_EXPLANATIONS[key]) return DEFAULT_ARTICLE_EXPLANATIONS[key];

  const colonKey = `${law.id}:${articleKey}`;
  if (internals && LEGAL_ARTICLE_TEXTS[colonKey]) return LEGAL_ARTICLE_TEXTS[colonKey];

  const firstNum = articleKey.match(/^(\d+(?:\.\d+)?)/);
  if (firstNum) {
    const singleKey = `${law.id}:${firstNum[1]}`;
    if (internals && LEGAL_ARTICLE_TEXTS[singleKey]) return LEGAL_ARTICLE_TEXTS[singleKey];
    const keyArt = LEGAL_KEY_ARTICLES[law.id]?.find(a => a.num === firstNum[1]);
    if (keyArt) {
      return internals
        ? `${keyArt.title}. ${keyArt.summary} ЕПСОК: ${keyArt.epsok}`
        : `${keyArt.title}. ${keyArt.summary}`;
    }
  }

  const label = articleKey.startsWith('гл.') || articleKey.startsWith('ч.')
    ? articleKey
    : `ст. ${articleKey}`;
  return `${label} ${law.code} — ${law.title}. ${law.summary}`;
}

function getArticleExplanation(lawId, articleKey, p = getActivePersona()) {
  const internals = canViewSystemInternals(p);
  const store = loadArticleExplanations();
  const k = articleExplStorageKey(lawId, articleKey);
  if (store[k]) return store[k];
  const colonKey = `${lawId}:${articleKey}`;
  if (internals && LEGAL_ARTICLE_TEXTS[colonKey]) return LEGAL_ARTICLE_TEXTS[colonKey];
  const law = LEGAL_BASE.find(l => l.id === lawId);
  if (law?.keyArticles) {
    const ka = law.keyArticles.find(a => a.num === articleKey || articleKey.includes(a.num));
    if (ka) {
      let text = ka.summary;
      if (internals && ka.epsok) text += `\n\nЕПСОК: ${ka.epsok}`;
      return text;
    }
  }
  return law ? getDefaultArticleExplanation(law, articleKey, p) : '';
}

function saveArticleExplanation(lawId, articleKey, text) {
  const store = loadArticleExplanations();
  store[articleExplStorageKey(lawId, articleKey)] = text;
  localStorage.setItem(ARTICLE_EXPL_STORAGE, JSON.stringify(store));
}

function renderLegalArticlesHtml(law) {
  const articlesStr = law.articles;
  if (!articlesStr || articlesStr.trim() === '—') {
    return `<span class="reg-law-art reg-law-art-empty">${escapeHtml(articlesStr || '—')}</span>`;
  }

  let prefix = '';
  const segments = articlesStr.split(/,\s*/);
  const parts = [];

  for (const segment of segments) {
    const trimmed = segment.trim();
    const m = trimmed.match(/^(ст\.\s*|ч\.\s*|гл\.\s*)(.+)$/i);
    let display;
    let articleKey;
    if (m) {
      prefix = m[1];
      display = trimmed;
      articleKey = normalizeArticleKey(prefix, m[2]);
    } else {
      display = trimmed;
      articleKey = normalizeArticleKey(prefix, trimmed);
    }

    parts.push(
      `<button type="button" class="reg-law-art-link" title="Пояснение статьи"` +
      ` data-law-id="${escapeHtml(law.id)}"` +
      ` data-law-code="${escapeHtml(law.code)}"` +
      ` data-law-title="${escapeHtml(law.title)}"` +
      ` data-article-key="${escapeHtml(articleKey)}"` +
      ` data-article-label="${escapeHtml(display)}">${escapeHtml(display)}</button>`
    );
  }

  return `<span class="reg-law-art">${parts.join('<span class="reg-law-art-sep">, </span>')}</span>`;
}

function bindLegalArticleClicks() {
  const resultsEl = document.getElementById('reg-laws-results');
  if (!resultsEl || resultsEl.dataset.articleBound) return;
  resultsEl.dataset.articleBound = '1';
  resultsEl.addEventListener('click', (e) => {
    const btn = e.target.closest('.reg-law-art-link');
    if (!btn) return;
    e.preventDefault();
    openArticleExplanationModal(
      btn.dataset.lawId,
      btn.dataset.lawCode,
      btn.dataset.lawTitle,
      btn.dataset.articleKey,
      btn.dataset.articleLabel
    );
  });
}

function openArticleExplanationModal(lawId, lawCode, lawTitle, articleKey, articleLabel) {
  articleExplanationCtx = { lawId, lawCode, lawTitle, articleKey, articleLabel };
  const titleEl = document.getElementById('article-explanation-title');
  const lawEl = document.getElementById('article-explanation-law');
  const textarea = document.getElementById('article-explanation-text');
  const label = articleLabel.startsWith('ст.') || articleLabel.startsWith('ч.') || articleLabel.startsWith('гл.')
    ? articleLabel
    : `ст. ${articleLabel}`;
  if (titleEl) titleEl.textContent = label;
  if (lawEl) lawEl.textContent = `${lawCode} · ${lawTitle}`;
  if (textarea) {
    const editable = canViewSystemInternals();
    textarea.value = getArticleExplanation(lawId, articleKey);
    textarea.readOnly = !editable;
    textarea.classList.toggle('article-explanation-readonly', !editable);
  }
  const fieldLabel = document.getElementById('article-explanation-field-label');
  const saveBtn = document.getElementById('article-explanation-save-btn');
  const editable = canViewSystemInternals();
  if (fieldLabel) {
    fieldLabel.textContent = editable
      ? 'Краткое пояснение (редактирование для админов)'
      : 'Краткое пояснение (только просмотр)';
  }
  if (saveBtn) saveBtn.classList.toggle('hidden', !editable);
  const law = getLegalDocById(lawId);
  const query = law ? (law.officialQuery || law.code) : lawCode;
  const pravoLink = document.getElementById('article-explanation-pravo');
  const consultantLink = document.getElementById('article-explanation-consultant');
  const searchQ = `${lawCode} ${articleLabel}`;
  if (pravoLink) pravoLink.href = legalPravoSearchUrl(searchQ);
  if (consultantLink) consultantLink.href = legalConsultantSearchUrl(searchQ);
  const asofEl = document.getElementById('article-explanation-asof');
  const meta = getLawSyncMeta(lawId);
  if (asofEl) {
    asofEl.textContent = meta
      ? `Актуально на: ${formatLegislationDateRu(meta.revisionDate)} · ${meta.version || ''}`
      : 'Актуально на: —';
  }
  document.getElementById('article-explanation-modal')?.classList.remove('hidden');
}

function closeArticleExplanationModal() {
  document.getElementById('article-explanation-modal')?.classList.add('hidden');
  articleExplanationCtx = null;
}

function saveArticleExplanationFromModal() {
  if (!canViewSystemInternals()) {
    showToast('Редактирование пояснений недоступно для вашей роли.');
    return;
  }
  if (!articleExplanationCtx) return;
  const text = document.getElementById('article-explanation-text')?.value.trim() || '';
  if (text.length < 10) {
    showToast('Пояснение должно содержать не менее 10 символов.');
    return;
  }
  saveArticleExplanation(articleExplanationCtx.lawId, articleExplanationCtx.articleKey, text);
  pushAuditEntry('Редактирование пояснения статьи', `${articleExplanationCtx.lawCode} ${articleExplanationCtx.articleLabel}`, 'ПОЛ-008');
  showToast('Пояснение сохранено локально.');
  closeArticleExplanationModal();
}

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

function renderLegalSyncFootnote(lawId) {
  const meta = getLawSyncMeta(lawId);
  if (!meta) return '';
  const updated = formatLegislationDateRu(meta.revisionDate);
  const checked = formatLegislationDateTimeRu(meta.lastCheckedAt);
  const isRecent = meta.lastUpdatedAt
    && (Date.now() - new Date(meta.lastUpdatedAt).getTime() < 7 * 24 * 60 * 60 * 1000);
  return `<footer class="reg-law-sync-foot">
    <span class="reg-law-sync-badge${isRecent ? ' reg-law-sync-badge-new' : ''}" title="Редакция от ${escapeHtml(updated)}">Обновлено: ${escapeHtml(updated)}</span>
    <span class="reg-law-sync-checked muted" title="Последняя проверка реестра">Проверено: ${escapeHtml(checked)}</span>
  </footer>`;
}

function renderLegalBaseCard(l) {
  const cat = LEGAL_BASE_CATEGORIES.find(c => c.id === l.category);
  const query = l.officialQuery || l.code;
  const pravoUrl = legalPravoSearchUrl(query);
  const consultantUrl = legalConsultantSearchUrl(l.consultantQuery || query);
  const keyCount = l.keyArticles?.length || 0;
  return `<article class="reg-law-card">
    <div class="reg-law-head">
      <button type="button" class="reg-law-title-btn" onclick="openLegalDocModal('${l.id}')" title="Карточка акта">${escapeHtml(l.code)}</button>
      <span class="reg-tag">${escapeHtml(LEGAL_DOC_TYPES[l.docType] || 'Акт')}</span>
    </div>
    <p class="reg-law-title">${escapeHtml(l.title)}</p>
    <p class="reg-law-summary">${escapeHtml(l.summary)}</p>
    ${renderLegalArticlesHtml(l)}
    ${keyCount ? `<p class="reg-law-key-hint muted">${keyCount} ключевых статей в справочнике · нажмите код акта для обзора</p>` : ''}
    ${renderLegalEpsokHtml(l.epsok)}
    <div class="reg-law-agencies">${l.agencies.map(a =>
      `<span>${escapeHtml(LEGAL_AGENCY_LABELS[a] || a)}</span>`
    ).join('')}</div>
    <div class="reg-law-card-foot">
      ${cat ? `<span class="reg-law-cat-tag">${escapeHtml(cat.icon)} ${escapeHtml(cat.label)}</span>` : '<span></span>'}
      <span class="reg-law-sources">
        <a href="${escapeHtml(pravoUrl)}" target="_blank" rel="noopener noreferrer" onclick="event.stopPropagation()">pravo.gov.ru ↗</a>
        <a href="${escapeHtml(consultantUrl)}" target="_blank" rel="noopener noreferrer" onclick="event.stopPropagation()">КонсультантПлюс ↗</a>
      </span>
    </div>
    ${renderLegalSyncFootnote(l.id)}
  </article>`;
}

function renderLegalDocArticleItems(law) {
  const articles = law.keyArticles || [];
  const internals = canViewSystemInternals();
  if (!articles.length) {
    return `<p class="muted legal-doc-no-articles">Ключевые статьи для этого акта в демо не разобраны. Используйте ссылки на официальные источники ниже или нажмите на статьи в карточке акта.</p>`;
  }
  return `<div class="legal-article-list">${articles.map(a => {
    const textKey = `${law.id}:${a.num}`;
    const imported = internals ? LEGAL_ARTICLE_TEXTS[textKey] : '';
    return `<details class="legal-article-item" open>
      <summary><strong>ст. ${escapeHtml(a.num)}</strong>${a.title ? ` — ${escapeHtml(a.title)}` : ''}</summary>
      <div class="legal-article-body">
        <p>${escapeHtml(a.summary)}</p>
        ${internals && a.epsok ? `<p class="reg-law-epsok"><span class="reg-law-epsok-label">ЕПСОК:</span> ${escapeHtml(a.epsok)}</p>` : ''}
        ${imported ? `<p class="legal-article-imported"><span class="legal-article-imported-label">Справка:</span> ${escapeHtml(imported)}</p>` : ''}
      </div>
    </details>`;
  }).join('')}</div>`;
}

function openLegalDocModal(lawId) {
  const law = getLegalDocById(lawId);
  if (!law) return;
  const query = law.officialQuery || law.code;
  document.getElementById('legal-doc-type').textContent = LEGAL_DOC_TYPES[law.docType] || 'Нормативный акт';
  document.getElementById('legal-doc-title').textContent = law.title;
  document.getElementById('legal-doc-code').textContent = law.code + (law.articles ? ' · ' + law.articles : '');
  document.getElementById('legal-doc-summary').textContent = law.summary;
  const epsokEl = document.getElementById('legal-doc-epsok');
  const internals = canViewSystemInternals();
  if (epsokEl) {
    if (internals && law.epsok) {
      epsokEl.innerHTML = `<span class="reg-law-epsok-label">ЕПСОК:</span> ${escapeHtml(law.epsok)}`;
      epsokEl.classList.remove('hidden');
    } else {
      epsokEl.innerHTML = '';
      epsokEl.classList.add('hidden');
    }
  }
  document.getElementById('legal-doc-disclaimer-dev')?.classList.toggle('hidden', !internals);
  const agenciesEl = document.getElementById('legal-doc-agencies');
  if (agenciesEl) {
    agenciesEl.innerHTML = law.agencies.map(a =>
      `<span>${escapeHtml(LEGAL_AGENCY_LABELS[a] || a)}</span>`
    ).join('');
  }
  const articlesEl = document.getElementById('legal-doc-articles');
  if (articlesEl) {
    articlesEl.innerHTML = `<h4 class="legal-doc-articles-title">Ключевые статьи (демо-справочник)</h4>${renderLegalDocArticleItems(law)}`;
  }
  const pravoLink = document.getElementById('legal-doc-pravo');
  const consultantLink = document.getElementById('legal-doc-consultant');
  if (pravoLink) pravoLink.href = legalPravoSearchUrl(query);
  if (consultantLink) consultantLink.href = legalConsultantSearchUrl(law.consultantQuery || query);
  document.getElementById('legal-doc-modal')?.classList.remove('hidden');
}

function closeLegalDocModal() {
  document.getElementById('legal-doc-modal')?.classList.add('hidden');
}

function renderLegalBase() {
  prepareLegalBaseFilters();
  renderLegislationSyncUi();
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
  } else if (regLegalCategory !== 'all') {
    resultsEl.innerHTML = `<div class="reg-law-grid">${filtered.map(renderLegalBaseCard).join('')}</div>`;
  } else {
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
  bindLegalArticleClicks();
}

function syncLegalInternalsVisibility() {
  const internals = canViewSystemInternals();
  document.getElementById('legal-doc-disclaimer-dev')?.classList.toggle('hidden', !internals);
  if (document.getElementById('reg-pane-laws')?.classList.contains('active')) renderLegalBase();
}

function prepareRegulationsView() {
  const kpiEl = document.getElementById('reg-kpi-laws');
  if (kpiEl) kpiEl.textContent = String(LEGAL_BASE.length);
  renderRegPolicies();
  void maybeAutoCheckLegislation({ silent: true });
  renderLegislationSyncUi();
  refreshLegislationImpactBanners();
  if (document.getElementById('reg-pane-laws')?.classList.contains('active')) renderLegalBase();
}

function renderPolicyCardHtml(p) {
  return `<button type="button" class="reg-policy-card" onclick="openPolicyDetailModal('${p.id}')" aria-label="${escapeHtml(p.code)}: ${escapeHtml(p.title)}">
    <span class="reg-code">${escapeHtml(p.code)}</span>
    <strong class="reg-policy-title">${escapeHtml(p.title)}</strong>
    <p>${escapeHtml(p.summary)}</p>
    <span class="reg-scope">${escapeHtml(p.scope)}</span>
    <span class="reg-policy-more">Подробнее →</span>
  </button>`;
}

function renderRegPolicies() {
  const root = document.getElementById('reg-policy-grid');
  if (!root) return;
  const byGroup = {};
  EPSOK_POLICIES.forEach(p => {
    if (!byGroup[p.group]) byGroup[p.group] = [];
    byGroup[p.group].push(p);
  });
  root.innerHTML = POLICY_GROUP_ORDER.filter(g => byGroup[g]?.length).map(g => `
    <section class="reg-policy-group">
      <h4 class="reg-policy-group-title">${escapeHtml(POLICY_GROUP_LABELS[g])}</h4>
      <div class="reg-policy-grid-inner">${byGroup[g].map(renderPolicyCardHtml).join('')}</div>
    </section>
  `).join('');
}

function openPolicyDetailModal(policyId) {
  const p = EPSOK_POLICIES.find(x => x.id === policyId);
  if (!p) return;
  const setText = (id, text) => {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
  };
  setText('policy-detail-code', p.code);
  setText('policy-detail-title', p.title);
  setText('policy-detail-summary', p.summary);
  setText('policy-detail-example', p.example);
  const canEl = document.getElementById('policy-detail-can');
  const cannotEl = document.getElementById('policy-detail-cannot');
  if (canEl) canEl.innerHTML = (p.can || []).map(x => `<li>${escapeHtml(x)}</li>`).join('');
  if (cannotEl) cannotEl.innerHTML = (p.cannot || []).map(x => `<li>${escapeHtml(x)}</li>`).join('');
  const moduleBtn = document.getElementById('policy-detail-module-btn');
  if (moduleBtn) {
    const showModule = p.viewId && canAccessView(p.viewId);
    moduleBtn.classList.toggle('hidden', !showModule);
    moduleBtn.textContent = showModule ? `Открыть: ${p.moduleLabel}` : '';
    moduleBtn.onclick = showModule
      ? () => { closePolicyDetailModal(); showView(p.viewId); }
      : null;
  }
  document.getElementById('policy-detail-modal')?.classList.remove('hidden');
}

function closePolicyDetailModal() {
  document.getElementById('policy-detail-modal')?.classList.add('hidden');
}

const HELP_SECTION_IDS = ['help-start', 'help-hotkeys', 'help-security', 'help-modules', 'help-graph', 'help-osint', 'help-horizon', 'help-faq'];
let helpNavClickLock = 0;

function setActiveInfoNav(blockId) {
  const nav = document.querySelector('#view-help .info-nav');
  if (!nav || !blockId) return;
  nav.querySelectorAll('.info-nav-item').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.info === blockId);
  });
}

function scrollInfo(blockId) {
  const view = document.getElementById('view-help');
  const el = document.getElementById(blockId);
  if (el && view) {
    const top = el.getBoundingClientRect().top - view.getBoundingClientRect().top + view.scrollTop;
    view.scrollTo({ top: Math.max(0, top - 16), behavior: 'smooth' });
  }
  setActiveInfoNav(blockId);
  helpNavClickLock = Date.now() + 600;
}

function updateHelpNavFromScroll() {
  if (Date.now() < helpNavClickLock) return;
  const view = document.getElementById('view-help');
  if (!view?.classList.contains('active')) return;

  const anchor = view.getBoundingClientRect().top + 100;
  let activeId = HELP_SECTION_IDS[0];
  let bestTop = -Infinity;
  for (const id of HELP_SECTION_IDS) {
    const block = document.getElementById(id);
    if (!block) continue;
    const top = block.getBoundingClientRect().top;
    if (top <= anchor && top > bestTop) {
      bestTop = top;
      activeId = id;
    }
  }
  setActiveInfoNav(activeId);
}

let helpNavObserver = null;

function initHelpNavSpy() {
  const view = document.getElementById('view-help');
  if (!view || view.dataset.helpSpyBound) return;
  view.dataset.helpSpyBound = '1';

  view.addEventListener('scroll', () => {
    if (Date.now() < helpNavClickLock) return;
    requestAnimationFrame(updateHelpNavFromScroll);
  }, { passive: true });

  if (typeof IntersectionObserver !== 'undefined') {
    helpNavObserver?.disconnect();
    helpNavObserver = new IntersectionObserver((entries) => {
      if (Date.now() < helpNavClickLock) return;
      const visible = entries
        .filter(e => e.isIntersecting)
        .sort((a, b) => b.intersectionRatio - a.intersectionRatio);
      if (visible[0]?.target?.id) setActiveInfoNav(visible[0].target.id);
    }, { root: view, rootMargin: '-15% 0px -60% 0px', threshold: [0, 0.15, 0.4] });
    HELP_SECTION_IDS.forEach(id => {
      const el = document.getElementById(id);
      if (el) helpNavObserver.observe(el);
    });
  }
}

function submitSupportTicket(e) {
  e.preventDefault();
  const category = document.getElementById('support-category').value;
  const priority = document.getElementById('support-priority').value;
  const subject = document.getElementById('support-subject').value.trim();
  const body = document.getElementById('support-body')?.value.trim() || '';
  const contact = document.getElementById('support-contact').value.trim();
  const ticketId = 'ОБР-' + Date.now().toString().slice(-6);
  const priorityLabel = { normal: 'обычный', high: 'высокий', critical: 'критичный' }[priority] || priority;
  const sla = SUPPORT_SLA_LABELS[priority] || '—';
  const ticket = {
    id: ticketId,
    category,
    priority,
    subject,
    body,
    contact,
    sla,
    status: 'open',
    createdAt: new Date().toLocaleString('ru-RU'),
    personaId: getActivePersona()?.id || null
  };
  const tickets = loadSupportTickets();
  tickets.unshift(ticket);
  saveSupportTickets(tickets);
  pushAuditEntry('Обращение в поддержку', `${ticketId} · ${subject}`, 'ПОЛ-005');
  document.getElementById('support-form').reset();
  updateSupportSlaHint();
  renderSupportTicketHistory();
  try { navigator.clipboard?.writeText?.(ticketId); } catch { /* noop */ }
  showToast(`Обращение ${ticketId} принято (${priorityLabel}, SLA ${sla}). Номер скопирован · ответ на ${contact || 'указанный контакт'}.`);
}

function loadSupportTickets() {
  try {
    const raw = localStorage.getItem(SUPPORT_TICKETS_STORAGE);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

function saveSupportTickets(tickets) {
  try {
    localStorage.setItem(SUPPORT_TICKETS_STORAGE, JSON.stringify(tickets.slice(0, 50)));
  } catch { /* noop */ }
}

const SUPPORT_TICKET_STATUS_LABELS = { open: 'Открыто', resolved: 'Закрыто' };

function renderSupportTicketHistory() {
  const host = document.getElementById('support-ticket-history');
  if (!host) return;
  const tickets = loadSupportTickets();
  if (!tickets.length) {
    host.innerHTML = '<p class="muted">Обращений пока нет — форма выше.</p>';
    return;
  }
  host.innerHTML = `<div class="table-scroll"><table class="data-table support-ticket-table"><thead><tr>
    <th>№</th><th>Тема</th><th>Приоритет</th><th>SLA</th><th>Статус</th><th>Создано</th><th></th>
  </tr></thead><tbody>${tickets.map(t => `<tr>
    <td><code>${escapeHtml(t.id)}</code></td>
    <td>${escapeHtml(t.subject)}</td>
    <td>${escapeHtml({ normal: 'обычный', high: 'высокий', critical: 'критичный' }[t.priority] || t.priority)}</td>
    <td>${escapeHtml(t.sla)}</td>
    <td><span class="status ${t.status === 'resolved' ? 'fulfilled' : 'progress'}">${SUPPORT_TICKET_STATUS_LABELS[t.status] || t.status}</span></td>
    <td class="muted">${escapeHtml(t.createdAt)}</td>
    <td><button type="button" class="btn-xs" onclick="copySupportTicketId('${t.id}')" title="Копировать номер">⎘</button></td>
  </tr>`).join('')}</tbody></table></div>`;
}

function getAppVersionFromScripts() {
  try {
    const scripts = Array.from(document.querySelectorAll('script[src]'));
    const versions = {};
    for (const s of scripts) {
      const src = s.getAttribute('src') || '';
      const m = src.match(/(app|security)\.js\?v=([^&]+)/);
      if (m) versions[m[1]] = m[2];
    }
    return versions;
  } catch {
    return {};
  }
}

function buildDiagnosticsPayload() {
  const now = new Date().toISOString();
  let persona = null;
  try {
    persona = typeof getActivePersona === 'function' ? getActivePersona() : null;
  } catch { /* noop */ }

  let sessionRaw = null;
  let rememberRaw = null;
  try { sessionRaw = sessionStorage.getItem(AUTH_STORAGE_KEY); } catch { /* noop */ }
  try { rememberRaw = localStorage.getItem(AUTH_REMEMBER_KEY); } catch { /* noop */ }

  const payload = {
    ts: now,
    app: {
      versions: getAppVersionFromScripts(),
      hostname: location.hostname,
      url: location.href
    },
    auth: {
      htmlAuthMode: document.documentElement.dataset.auth || null,
      hasSession: !!sessionRaw,
      sessionLen: sessionRaw ? sessionRaw.length : 0,
      hasRemember: !!rememberRaw,
      rememberLen: rememberRaw ? rememberRaw.length : 0
    },
    user: currentUser ? {
      username: currentUser.username,
      personaId: currentUser.personaId || null,
      contourLabel: currentUser.contourLabel || null
    } : null,
    persona: persona ? {
      id: persona.id,
      roleType: persona.roleType,
      role: persona.role,
      allowedViewsCount: Array.isArray(persona.allowedViews) ? persona.allowedViews.length : 0
    } : null,
    ui: {
      activeView: (() => { try { return sessionStorage.getItem(ACTIVE_VIEW_KEY); } catch { return null; } })(),
      secureContext: !!globalThis.isSecureContext,
      hasWebCrypto: !!EpsokSecurity?.hasWebCrypto,
      userAgent: navigator.userAgent,
      idleRemainingMs: isAppLoggedIn() && sessionActivityDeadline
        ? Math.max(0, sessionActivityDeadline - Date.now())
        : null
    },
    security: typeof EpsokSecurity?.getSecurityProfile === 'function'
      ? EpsokSecurity.getSecurityProfile()
      : null
  };

  return payload;
}

async function collectDiagnosticsAndCopy() {
  const payload = buildDiagnosticsPayload();
  const text = JSON.stringify(payload, null, 2);
  const supportBody = document.getElementById('support-body');
  if (supportBody && !supportBody.value.includes('--- Диагностика ЕПСОК')) {
    const block = `--- Диагностика ЕПСОК (авто) ---\n${text}\n---\n\n`;
    supportBody.value = block + supportBody.value;
  }

  const tryClipboard = async () => {
    if (!navigator.clipboard?.writeText) throw new Error('clipboard-not-available');
    await navigator.clipboard.writeText(text);
  };

  try {
    await tryClipboard();
    showToast('Диагностика скопирована в буфер обмена.');
    return;
  } catch (_) {
    // Fallback: скачиваем файл, чтобы ничего не терять
    try {
      const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `epsok-diagnostics-${Date.now()}.txt`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      showToast('Диагностика скачана в файл.');
    } catch (e) {
      // Последний fallback: показываем в alert
      alert(text);
    }
  }
}

function syncSidebarNavTitles() {
  document.querySelectorAll('.nav-item').forEach((item) => {
    if (item.classList.contains('nav-locked')) return;
    const label = item.querySelector('.nav-label')?.textContent?.replace(/\s*🔒\s*$/, '').trim();
    if (label) item.title = label;
  });
  const corp = document.getElementById('sidebar-corp-mail');
  if (corp) corp.title = 'Корпоративная почта';
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

function initModalDismiss() {
  if (window.__epsokModalDismissBound) return;
  window.__epsokModalDismissBound = true;

  const closeByOverlayId = {
    'demo-role-modal': closeDemoRoleModal,
    'request-modal': closeRequestModal,
    'request-simulate-modal': closeRequestSimulateModal,
    'request-fulfill-modal': closeRequestFulfillModal,
    'request-result-modal': closeRequestResultModal,
    'access-request-modal': closeAccessRequestModal,
    'hr-request-modal': closeHrRequestModal,
    'osint-import-modal': closeOsintImportModal,
    'mail-compose-modal': closeMailCompose,
    'new-case-modal': closeNewCaseModal,
    'case-team-modal': closeCaseTeamAddModal,
    'discipline-modal': closeDisciplineModal,
    'article-explanation-modal': closeArticleExplanationModal,
    'legal-doc-modal': closeLegalDocModal,
    'policy-detail-modal': closePolicyDetailModal,
    'victim-notification-modal': closeVictimNotificationModal,
    'deadline-extension-modal': closeDeadlineExtensionModal,
    'cluster-hub-modal': closeClusterHub,
    'graph-peer-detail-modal': closeGraphPeerDetailModal,
    'shortcuts-modal': closeShortcutsModal
  };

  document.querySelectorAll('.modal-overlay').forEach(overlay => {
    const closeFn = closeByOverlayId[overlay.id];
    if (!closeFn) return;

    let interactionStartedInside = false;
    const panel = overlay.querySelector('.modal-panel');

    panel?.addEventListener('pointerdown', () => {
      interactionStartedInside = true;
    }, true);

    overlay.addEventListener('pointerdown', (e) => {
      if (e.target === overlay) interactionStartedInside = false;
    });

    overlay.addEventListener('pointerup', (e) => {
      if (overlay.classList.contains('hidden')) {
        interactionStartedInside = false;
        return;
      }
      if (e.target === overlay && !interactionStartedInside) closeFn();
      interactionStartedInside = false;
    });
  });
}

function initSidebar() {
  applySidebarCollapsedState();
  syncSidebarNavTitles();
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
  initHelpNavSpy();
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
  if (!canSwitchDemoPersona()) {
    showToast('Смена роли недоступна для вашей учётной записи.');
    return;
  }
  renderDemoPersonaModal();
  document.getElementById('demo-role-modal')?.classList.remove('hidden');
}

function closeDemoRoleModal() {
  document.getElementById('demo-role-modal')?.classList.add('hidden');
}

function getPersonaHierarchyBadge(p) {
  if (p.roleType === 'beta_root') return { kind: 'beta_root', label: 'Высший доступ' };
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
  const rank = { manager: 0, beta_root: 0, tech_admin: 0, func_admin: 1, subordinate: 2, prosecutor: 3, executor: 4, analyst: 5, court: 6, external: 7 };
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
  const username = currentUser?.username;
  el.innerHTML = demoPersonaGroups.map(g => {
    const sorted = sortPersonaIdsForGroup(g.ids.filter(id => canUsePersona(id, username)));
    if (!sorted.length) return '';
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
  if (!canUsePersona(personaId)) {
    showToast('ПОЛ-008: эта роль недоступна для вашей учётной записи.');
    pushAuditEntry('Отклонена смена роли', personaId, 'ПОЛ-008');
    return;
  }
  activePersonaId = personaId;
  if (currentUser) {
    void saveSession(currentUser.username, !!localStorage.getItem(AUTH_REMEMBER_KEY), personaId, true);
  }
  closeDemoRoleModal();
  profileViewPersonaId = null;
  profileTab = 'card';
  staffTab = personaId === 'TECH_ADMIN' || personaId === 'BETA_TAKURA' ? 'structures' : personaId === 'FUNC_ADMIN' ? 'accounts' : 'team';
  activeAdminModule = personaId === 'TECH_ADMIN' || personaId === 'BETA_TAKURA' ? 'SVC' : personaId === 'FUNC_ADMIN' ? 'USR' : activeAdminModule;
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

function canAccessAuditJournal(p = getActivePersona()) {
  return isTechAdminPersona(p);
}

function syncUserMenuAuditAccess(p = getActivePersona()) {
  document.getElementById('user-menu-audit-export')?.classList.toggle('hidden', !canAccessAuditJournal(p));
}

function syncUserMenuDemoAccess(username = currentUser?.username) {
  const allowed = canSwitchDemoPersona(username);
  document.querySelector('#user-menu-dropdown button[onclick*="openDemoRoleModal"]')?.classList.toggle('hidden', !allowed);
  document.querySelector('.demo-badge-btn')?.classList.toggle('hidden', !allowed);
}

function isFuncAdminPersona(p = getActivePersona()) {
  return getAdminKind(p) === 'func';
}

function isBetaRootPersona(p = getActivePersona()) {
  return p?.roleType === 'beta_root';
}

function hasLeadCapabilities(p = getActivePersona()) {
  return !!(p?.isManager || p?.roleType === 'inv_lead' || isBetaRootPersona(p));
}

function syncSidebarScrollMode(p = getActivePersona()) {
  document.getElementById('app-sidebar')?.classList.toggle('sidebar--scroll-nav', isBetaRootPersona(p));
}

function isAnyAdminPersona(p = getActivePersona()) {
  return !!getAdminKind(p);
}

function canViewSystemInternals(p = getActivePersona()) {
  return isTechAdminPersona(p) || isFuncAdminPersona(p);
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
  let mods;
  if (isBetaRootPersona(p)) mods = adminModules.slice();
  else {
    const kind = getAdminKind(p);
    if (!kind) return [];
    mods = adminModules.filter(m => m.kinds?.includes(kind));
  }
  if (!canAccessAuditJournal(p)) mods = mods.filter(m => m.id !== 'LOG');
  return mods;
}

function ensureAdminModuleAllowed() {
  const mods = getAdminModulesForPersona();
  if (!mods.some(m => m.id === activeAdminModule)) {
    activeAdminModule = mods[0]?.id || 'SVC';
  }
}

function getStructuresAgencyGroups() {
  const p = getActivePersona();
  if (isBetaRootPersona(p)) return demoPersonaGroups;
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
    const hasAccess = allowed.has(view);
    const canRequest = !hasAccess && shouldOfferAccessRequest(view, p);
    if (hasAccess) {
      btn.classList.remove('hidden', 'nav-locked');
    } else if (canRequest) {
      btn.classList.remove('hidden');
      btn.classList.add('nav-locked');
      const meta = ACCESS_FEATURES[view];
      btn.title = meta
        ? `Нет доступа · ${meta.policy} · нажмите для заявки`
        : 'Запросить доступ к модулю';
    } else {
      btn.classList.toggle('hidden', true);
      btn.classList.remove('nav-locked');
      btn.removeAttribute('title');
    }
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
  syncSidebarNavTitles();
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
  const inCaseContext = !!(c && personaCanBrowseCase(c.id) && caseViews.includes(currentView));

  if (pill) {
    pill.textContent = contourLine;
    pill.title = `${p.headerContour || 'Контур'} · ${p.name}`;
    pill.classList.remove('hidden');
  }
  if (sub) {
    sub.classList.remove('status-pill');
    sub.textContent = getHeaderSubtitle(currentView, p, region, c, inCaseContext);
  }
  updateHeaderStatusSummary();
}

function isHeaderStatusCompact() {
  return localStorage.getItem(HEADER_STATUS_COMPACT_STORAGE) !== '0';
}

function applyHeaderStatusCompact() {
  const cluster = document.getElementById('header-status-cluster');
  const toggle = document.getElementById('header-status-toggle');
  if (!cluster) return;
  const compact = isHeaderStatusCompact();
  cluster.classList.toggle('is-compact', compact);
  if (toggle) {
    toggle.setAttribute('aria-expanded', compact ? 'false' : 'true');
    toggle.textContent = compact ? '●' : '▾';
    toggle.setAttribute('aria-label', compact ? 'Показать статус контура и защиты' : 'Скрыть статус контура');
  }
  updateHeaderStatusSummary();
}

function updateHeaderStatusSummary() {
  const toggle = document.getElementById('header-status-toggle');
  const contourPill = document.getElementById('contour-pill');
  if (!toggle) return;
  const online = navigator.onLine;
  toggle.classList.toggle('header-status-offline', !online);
  const contour = contourPill?.textContent?.trim() || 'Контур';
  const network = online ? 'В сети' : 'Офлайн';
  toggle.title = `${network} · ${contour}`;
}

function toggleHeaderStatusCluster() {
  localStorage.setItem(HEADER_STATUS_COMPACT_STORAGE, isHeaderStatusCompact() ? '0' : '1');
  applyHeaderStatusCompact();
}

function applyDemoPersona() {
  const p = getActivePersona();
  const nameEl = document.getElementById('user-name');
  const profileBtn = document.getElementById('user-info-btn');
  if (nameEl) nameEl.textContent = p.name;
  if (profileBtn) {
    profileBtn.dataset.initials = p.avatar || p.name.split(/\s+/).map((w) => w[0]).join('').slice(0, 2);
    profileBtn.title = p.name;
  }
  const corpEmail = getCorporateEmail(p.id);
  const corpEmailEl = document.getElementById('sidebar-corp-email');
  if (corpEmailEl) corpEmailEl.textContent = corpEmail;
  updateMailSidebarBadge();
  updateRequestsSidebarBadge();
  updateHeaderContext();
  updateSecurityStrip();
  syncMailAdminVisibility();
  syncLegalInternalsVisibility();
  const platformStatus = document.getElementById('platform-status-pill');
  if (platformStatus) platformStatus.classList.toggle('hidden', !['admin', 'func_admin'].includes(p.roleType) && !isBetaRootPersona(p));

  updateNavigationForPersona(p);
  syncSidebarScrollMode(p);
  syncCapabilityButtons(p);
  syncAccessRequestLink(p);
  syncUserMenuAuditAccess(p);
  syncUserMenuDemoAccess(currentUser?.username);
  refreshHeaderChrome();

  caseFilterScope = getDefaultCaseFilterScope(p);
  loadCasesFiltersState();
  loadRequestsFiltersState();
  loadSuspectsFiltersState();
  applyPersonaCaseDefaults();
  renderDashboard();
  const currentView = document.querySelector('.view.active')?.id?.replace('view-', '');
  if (currentView === 'cases') renderCasesRegistry();
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
  const regionSel = document.getElementById('cases-filter-region');
  if (!regionSel) return;
  applyCaseFilterDefaults(caseFilterScope);
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
  const modes = ['investigator', 'executor', 'prosecutor', 'analyst', 'court'];
  modes.forEach(m => {
    const el = document.getElementById(`dash-${m}`);
    if (el) el.classList.add('hidden');
  });
  const mode = p.dashboardMode || 'investigator';
  if (mode === 'admin' || mode === 'func_admin') return;

  const panel = document.getElementById(`dash-${mode}`);
  if (panel) panel.classList.remove('hidden');
  if (mode === 'investigator') renderInvestigatorDashboard(p);
  if (mode === 'executor') renderExecutorDashboard(p);
  if (mode === 'prosecutor') renderProsecutorDashboard(p);
  if (mode === 'analyst') renderAnalystDashboard(p);
  if (mode === 'court') renderCourtDashboard(p);
  refreshHeaderChrome();
}

function renderContinueWorkPanel(p) {
  const recent = getRecentCasesForSearch(4);
  const bookmarkIds = loadCaseBookmarks();
  const bookmarked = bookmarkIds
    .filter(id => personaCanBrowseCase(id) && getCaseById(id))
    .slice(0, 4)
    .map(id => getCaseById(id));
  const items = [];
  const seen = new Set();
  for (const c of [...bookmarked, ...recent]) {
    if (!c || seen.has(c.id)) continue;
    seen.add(c.id);
    items.push(c);
    if (items.length >= 5) break;
  }
  if (!items.length) return '';

  const bookmarkSet = new Set(bookmarkIds);
  return `<div class="panel dash-continue-panel">
    <div class="panel-header">
      <h2>Продолжить работу</h2>
      <span class="muted dash-continue-hint">★ избранное · недавние</span>
    </div>
    <ul class="dash-continue-list">
      ${items.map(c => `<li>
        <button type="button" class="dash-continue-item" onclick="openCase('${c.id}')">
          ${bookmarkSet.has(c.id) ? '<span class="dash-continue-star" aria-hidden="true">★</span>' : ''}
          <span class="dash-continue-id">${escapeHtml(c.id)}</span>
          <span class="muted dash-continue-meta">${escapeHtml((c.article || '').replace(' УК РФ', ''))}</span>
          ${c.daysLeft != null && c.daysLeft <= 7 ? `<span class="dash-continue-urgent">${c.daysLeft} дн.</span>` : ''}
        </button>
      </li>`).join('')}
    </ul>
  </div>`;
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

function renderInvestigatorDashboard(p) {
  const kpiEl = document.getElementById('dash-investigator-kpi');
  const panelsEl = document.getElementById('dash-investigator-panels');
  if (!kpiEl) return;

  const urgentCases = getPersonaScopedCases().filter(c => c.daysLeft != null && c.daysLeft <= 7);
  const cards = [];
  if (canAccessView('cases', p)) {
    cards.push(renderKpiCard({
      value: getPersonaScopedCases().length,
      label: 'Дела в реестре',
      trend: '+12 за месяц',
      trendType: 'up',
      variant: 'cases',
      icon: '◫',
      id: 'kpi-cases-count',
      onclick: "showView('cases')"
    }));
  }
  if (canAccessView('deadlines', p)) {
    cards.push(renderKpiCard({
      value: urgentCases.length || 8,
      label: 'Истекают сроки (7 дн.)',
      trend: 'требуют внимания',
      trendType: 'warn',
      variant: 'deadlines',
      icon: '⏱',
      onclick: "showView('deadlines')"
    }));
  }
  if (canAccessView('requests', p)) {
    cards.push(renderKpiCard({
      value: platformRequests.filter(r => requestMatchesPersona(r, p)).length || 34,
      label: 'Запросов данных',
      trend: 'межвед · ведомство · отдел',
      trendType: 'up',
      variant: 'requests',
      icon: '⇄',
      onclick: "showView('requests')"
    }));
  }
  if (canViewOsint(p)) {
    cards.push(renderKpiCard({
      value: 6,
      label: 'Проверки открытых источников',
      trend: canLaunchOsintScan(p) ? '41 находка → граф' : 'только просмотр',
      trendType: 'up',
      variant: 'osint',
      icon: '⌕',
      onclick: "showView('osint')"
    }));
  }
  if (canAccessView('horizon', p)) {
    cards.push(renderKpiCard({
      value: 3,
      label: 'Сигналы «Горизонт»',
      trend: 'Совпадение · МВ-2847',
      trendType: 'up',
      variant: 'horizon',
      icon: '◈',
      onclick: "showView('horizon')"
    }));
  }
  if (canAccessView('graph', p)) {
    cards.push(renderKpiCard({
      value: 23,
      label: 'Связи установлены',
      trend: '+340% к 2026 г.',
      trendType: 'up',
      variant: 'links',
      icon: '◎',
      onclick: "showView('graph')"
    }));
  }
  kpiEl.innerHTML = cards.join('');

  if (!panelsEl) return;
  const panels = [];
  const impact = loadLegislationImpact();
  if (impact?.cases?.length && canAccessView('cases', p)) {
    panels.push(`<div class="legislation-impact-banner dashboard-legislation-banner" role="status">${renderLegislationImpactBannerHtml(impact, { compact: true })}</div>`);
  }
  if (canAccessView('cases', p)) {
    const continuePanel = renderContinueWorkPanel(p);
    if (continuePanel) panels.push(continuePanel);
  }
  if (hasLeadCapabilities(p) && canAccessView('requests', p)) {
    const overdue = getOverdueRequestsForPersona(p);
    if (overdue.length) {
      panels.push(`<div class="dashboard-sla-banner" role="alert">
        <strong>${overdue.length} запрос(ов) просрочено SLA</strong> · требуется контроль исполнителей
        <button type="button" class="btn-sm" style="margin-left:0.5rem" onclick="showView('requests')">Открыть запросы</button>
      </div>`);
    }
  }
  const clusterCase = getPersonaScopedCases().find(c => c.cluster === 'МВ-2847');
  if (clusterCase && canAccessView('cases', p)) {
    const clusterStats = getClusterEntityCount('МВ-2847');
    const clusterTokens = (CLUSTER_SHARED_TOKENS['МВ-2847'] || []).slice(0, 2).map(t => escapeHtml(t)).join(' · ');
    panels.push(`<div class="dashboard-sla-banner dashboard-cluster-banner" role="status">
      <div class="dashboard-cluster-head">
        <span>Дело <button type="button" class="case-link" onclick="openCase('${clusterCase.id}')">${clusterCase.id}</button> в кластере <strong>МВ-2847</strong></span>
        <button type="button" class="btn-sm" onclick="openClusterHub('МВ-2847')">Хаб кластера</button>
      </div>
      <p class="dashboard-cluster-meta muted">Мошенничество · ${clusterStats.regions} регионов · ${clusterStats.cases} дел · ${clusterStats.entities} общих токенов${clusterTokens ? ` · ${clusterTokens}` : ''}</p>
    </div>`);
  }
  if (canAccessView('cases', p) && canAccessView('deadlines', p)) {
    const rows = urgentCases.slice(0, 3);
    const fallback = [
      { id: 'ЕПСОК-2028-004521', article: '159.3 УК', stage: 'Следствие', daysLeft: 2, danger: true },
      { id: 'ЕПСОК-2028-003891', article: '228.1 УК', stage: 'Дознание', daysLeft: 5, danger: false },
      { id: 'ЕПСОК-2028-005102', article: '105 УК', stage: 'Следствие', daysLeft: 6, danger: false }
    ];
    const data = rows.length ? rows : fallback;
    panels.push(`<div class="panel">
      <div class="panel-header">
        <h2>Дела с критическими сроками</h2>
        <button type="button" class="btn-sm" onclick="showView('cases')">Весь реестр</button>
      </div>
      <div class="table-scroll dashboard-table-scroll">
        <table class="data-table dashboard-deadlines-table">
          <thead><tr><th>Дело</th><th>Статья</th><th>Этап</th><th>Осталось</th></tr></thead>
          <tbody>${data.map(c => `<tr class="${c.daysLeft != null && c.daysLeft <= 3 ? 'row-danger' : 'row-warning'}">
            <td><button type="button" class="case-link" onclick="openCase('${c.id}')">${c.id}</button></td>
            <td>${(c.article || '').replace(' УК РФ', '')}</td>
            <td>${escapeHtml(c.stage || '—')}</td>
            <td>${c.daysLeft != null ? `${c.daysLeft} дн.` : '—'}</td>
          </tr>`).join('')}
          </tbody>
        </table>
      </div>
    </div>`);
  }
  if (canAccessView('graph', p)) {
    panels.push(`<div class="panel">
      <h2>Федеральные связи</h2>
      <div class="cluster-list">
        <div class="cluster-item">
          <span class="cluster-tag fraud">Мошенничество</span>
          <span>Кластер МВ-2847 · 5 регионов · 47 дел</span>
          <button class="btn-sm" onclick="openClusterHub('МВ-2847')">Хаб кластера</button>
          <button class="btn-sm" onclick="showView('graph')">Граф</button>
        </div>
        ${canAccessView('horizon', p) ? `<div class="cluster-item">
          <span class="cluster-tag drugs">Наркотики</span>
          <span>Кластер МВ-1923 · 3 региона · 12 дел</span>
          <button class="btn-sm" onclick="showView('horizon')">Горизонт</button>
        </div>` : `<div class="cluster-item">
          <span class="cluster-tag drugs">Наркотики</span>
          <span>Кластер МВ-1923 · 3 региона · 12 дел</span>
          <button class="btn-sm" onclick="showView('graph')">Открыть граф</button>
        </div>`}
        <div class="cluster-item">
          <span class="cluster-tag eco">Экономика</span>
          <span>Кластер МВ-3102 · 8 регионов · 23 дела</span>
          <button class="btn-sm" onclick="showView('graph')">Открыть граф</button>
        </div>
      </div>
    </div>`);
  }
  if (hasLeadCapabilities(p) && canAccessView('requests', p)) {
    const roi = getManagerRoiMetrics(p);
    panels.push(`<div class="panel manager-roi-panel">
      <h2>Эффективность запросов · подразделение</h2>
      <div class="manager-roi-grid">
        <div class="manager-roi-stat"><span class="manager-roi-value">${roi.fulfilledCount}</span><span class="manager-roi-label">исполнено</span></div>
        <div class="manager-roi-stat"><span class="manager-roi-value">${roi.avgResponse}</span><span class="manager-roi-label">среднее время ответа</span></div>
        <div class="manager-roi-stat"><span class="manager-roi-value">${roi.pendingCount}</span><span class="manager-roi-label">в работе</span></div>
      </div>
      <p class="muted manager-roi-hint">Демо-метрика SLA · межвед и внутренние запросы региона</p>
    </div>`);
    panels.push(renderStaffWorkloadPanel(p));
    panels.push(renderRequestAnalyticsChart(p));
  }
  panelsEl.innerHTML = panels.join('');
  panelsEl.classList.toggle('hidden', panels.length === 0);
}

function isExecutorBlindContour(p = getActivePersona()) {
  return p.roleType === 'executor' && p.dashboardMode === 'executor';
}

function redactRequestForExecutor(r, field) {
  const val = field === 'subject' ? r.subject : field === 'from' ? r.from : field === 'legal' ? r.legal : '';
  if (!val) return field === 'subject' ? '<span class="muted">—</span>' : '—';
  if (field === 'subject') {
    const redacted = String(val)
      .replace(/ЕПСОК-\d{4}-\d+/gi, 'Дело №***')
      .replace(/дело\s+[\wА-Яа-яЁё-]+/gi, 'объект №***');
    return escapeHtml(redacted);
  }
  if (field === 'from') {
    const dept = String(val).split('·')[0]?.trim() || 'Подразделение инициатора';
    return escapeHtml(dept + ' · <скрыто>');
  }
  if (field === 'legal') {
    return escapeHtml(String(val).replace(/дело\s+[\w-]+/gi, 'объект №***'));
  }
  return escapeHtml(val);
}

function renderExecutorBlindBanner() {
  return `<aside class="executor-blind-banner" role="status">
    <strong>Слепой контур исполнителя</strong>
    <span class="muted">Вы видите только запрос: тип, объект и основание. Номер дела, ФИО следователя и содержание карточки скрыты (ПОЛ-003).</span>
  </aside>`;
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
  el.innerHTML = `
    ${renderExecutorBlindBanner()}
    <div class="panel">
      <div class="panel-header"><h2>Входящие запросы · ${escapeHtml(p.execAgency || p.group)}</h2>
        <button type="button" class="btn-sm" onclick="showView('requests')">Все запросы</button>
      </div>
      <div class="table-scroll">
        <table class="data-table">
          <thead><tr><th>ID</th><th>Уровень</th><th>Тип</th><th>Кого / что</th><th>От кого</th><th>Статус</th><th>SLA</th><th></th></tr></thead>
          <tbody>${data.map(r => `
            <tr><td>${r.id}</td><td>${renderRequestScopeBadge(r.scope)}</td><td>${escapeHtml(r.type)}</td>
            <td class="req-subject-cell">${redactRequestForExecutor(r, 'subject')}</td>
            <td>${redactRequestForExecutor(r, 'from')}</td>
            <td><span class="status ${r.status}">${requestStatusLabels[r.status] || r.status}</span></td>
            <td>${renderRequestSlaCell(r)}</td>
            <td class="req-actions-cell">${renderRequestActions(r, p)}</td></tr>`).join('')}
          </tbody>
        </table>
      </div>
    </div>`;
}

function getCaseRelatedRequests(caseId) {
  const c = getCaseById(caseId);
  if (!c) return [];
  const leadToken = c.lead?.split(' ')[0] || '';
  return platformRequests.filter(r =>
    r.subject?.includes(caseId) || (leadToken && r.from?.includes(leadToken)) || r.legal?.includes(caseId)
  );
}

function getCaseHealthMetrics(caseId) {
  const c = getCaseById(caseId);
  if (!c) return null;
  const nodeCount = countGraphNodesForCase(caseId);
  const objectHints = (c.figurants?.length || 0) + (c.keyObjects?.length || 0);
  const minNodes = Math.max(2, Math.min(objectHints, 4));
  const graphGap = nodeCount < minNodes;
  const backlog = getCaseRelatedRequests(caseId)
    .filter(r => ['progress', 'submitted', 'draft'].includes(r.status)).length;
  let deadlineRisk = 'ok';
  if (c.daysLeft != null) {
    if (c.daysLeft <= 3) deadlineRisk = 'critical';
    else if (c.daysLeft <= 7) deadlineRisk = 'warning';
    else if (c.daysLeft <= 14) deadlineRisk = 'watch';
  }
  return { deadlineRisk, graphGap, graphNodes: nodeCount, requestBacklog: backlog, daysLeft: c.daysLeft };
}

const CASE_HEALTH_LABELS = {
  critical: 'Критический',
  warning: 'Риск',
  watch: 'Контроль',
  ok: 'Норма'
};

function renderCaseHealthRiskBadge(level) {
  const cls = level === 'critical' ? 'critical' : level === 'warning' ? 'warning' : level === 'watch' ? 'watch' : 'ok';
  return `<span class="case-health-risk case-health-risk--${cls}">${CASE_HEALTH_LABELS[level] || level}</span>`;
}

function getCaseRiskLevel(caseId) {
  const m = getCaseHealthMetrics(caseId);
  if (!m) return 'норма';
  if (m.deadlineRisk === 'critical' || (m.graphGap && m.daysLeft != null && m.daysLeft <= 7)) return 'критично';
  if (m.deadlineRisk === 'warning' || m.deadlineRisk === 'watch' || m.requestBacklog > 2) return 'внимание';
  return 'норма';
}

function renderCaseRiskBadge(caseId) {
  const level = getCaseRiskLevel(caseId);
  const cls = level === 'критично' ? 'critical' : level === 'внимание' ? 'warning' : 'ok';
  return `<span class="case-risk-badge case-risk-badge--${cls}" title="Индикатор риска дела">${level}</span>`;
}

function getDemoNow() {
  return new Date(2028, 5, 15, 12, 0, 0);
}

const REQUEST_SLA_HOURS = {
  interagency: 72,
  intra_agency: 24,
  intra_department: 4
};

function parseDemoDateRu(str) {
  if (!str || str === '—') return null;
  const m = String(str).trim().match(/^(\d{2})\.(\d{2})\.(\d{4})(?:\s+(\d{2}):(\d{2}))?/);
  if (!m) return null;
  return new Date(+m[3], +m[2] - 1, +m[1], +(m[4] || 0), +(m[5] || 0), 0);
}

function getRequestSlaDueAt(r) {
  if (r.slaDueAt) return parseDemoDateRu(r.slaDueAt) || new Date(r.slaDueAt);
  const base = parseDemoDateRu(r.createdAt || r.sent);
  if (!base) return null;
  const hours = REQUEST_SLA_HOURS[r.scope] || REQUEST_SLA_HOURS.interagency;
  return new Date(base.getTime() + hours * 3600000);
}

function isRequestSlaOverdue(r) {
  if (!r || ['fulfilled', 'draft'].includes(r.status)) return false;
  const due = getRequestSlaDueAt(r);
  if (!due) return false;
  return getDemoNow() > due;
}

function getOverdueRequestsForPersona(p = getActivePersona()) {
  return platformRequests.filter(r => requestMatchesPersona(r, p) && isRequestSlaOverdue(r));
}

function renderRequestSlaCell(r) {
  if (r.status === 'fulfilled') return escapeHtml(r.sla || '✓');
  if (isRequestSlaOverdue(r)) {
    return `<span class="sla-overdue-badge" title="Просрочен SLA">просрочен</span>`;
  }
  return `<span class="sla-ok-badge">${escapeHtml(r.sla || '—')}</span>`;
}

let activeClusterHubId = 'МВ-2847';
let activeRequestHighlightId = null;
let agenciesSearchQuery = '';
let agenciesCategoryFilter = '';
let activeClusterCompareA = null;
let activeClusterCompareB = null;
let caseActivityFilter = 'все';
let activeDeadlineExtensionCaseId = null;
let activeVictimNotificationCaseId = null;
let casesBookmarkFilter = false;
let casesSearchQuery = '';
let casesStatusFilter = 'all';
let deadlinesViewMode = 'list';
let pendingCaseStatusChange = null;
let pendingNavSequence = null;
let pendingNavTimer = null;

const graphPathState = { picks: [], pathNodeIds: null, pathEdges: null };

const CLUSTER_SHARED_TOKENS = {
  'МВ-2847': ['SIM +7***8901', 'Счёт ***4521', 'ООО «Номинал»', 'suspect.fraud@mail.ru'],
  'МВ-1923': ['ХЭШ-7B3C', 'Telegram @kazan_sim'],
  'МВ-3102': ['ИНН 7701234567', 'Криптокошелёк USDT']
};

const CLUSTER_TIMELINE_EVENTS = {
  'МВ-2847': [
    { at: '05.02.2028', region: 'Москва', text: 'Связь по счёту ***4521 · дело СК' },
    { at: '14.03.2028', region: 'Татарстан', text: 'Совпадение SIM +7***8901' },
    { at: '12.06.2028', region: 'Краснодар', text: 'Индекс «Горизонт» · кластер подтверждён' },
    { at: '14.06.2028', region: 'Федеральный', text: 'Коллизия ФСБ · ХЭШ-9F2A · согласование РГ' }
  ]
};

function getClusterCases(clusterId) {
  return casesRegistry.filter(c => c.cluster === clusterId);
}

function getClusterEntityCount(clusterId) {
  const cases = getClusterCases(clusterId);
  const tokens = new Set(CLUSTER_SHARED_TOKENS[clusterId] || []);
  cases.forEach(c => {
    (c.keyObjects || []).forEach(o => tokens.add(o.label));
    (c.figurants || []).forEach(f => tokens.add(f.name));
  });
  return { cases: cases.length, entities: tokens.size, regions: new Set(cases.map(c => c.region)).size };
}

function renderClusterHubPanel(clusterId) {
  const stats = getClusterEntityCount(clusterId);
  const cases = getClusterCases(clusterId);
  const tokens = CLUSTER_SHARED_TOKENS[clusterId] || [];
  const timeline = CLUSTER_TIMELINE_EVENTS[clusterId] || [];
  const tech = canViewSystemInternals();
  const compareA = activeClusterCompareA && cases.some(c => c.id === activeClusterCompareA) ? activeClusterCompareA : cases[0]?.id || '';
  const compareB = activeClusterCompareB && cases.some(c => c.id === activeClusterCompareB) ? activeClusterCompareB : cases[1]?.id || '';
  return `
    <p class="muted">Федеральный кластер · обезличенные совпадения · ПОЛ-007${tech ? ` · id: ${escapeHtml(clusterId)}` : ''}</p>
    <div class="cluster-hub-stats">
      <div class="cluster-hub-stat"><span class="cluster-hub-stat-val">${stats.cases}</span><span class="cluster-hub-stat-label">дел в реестре</span></div>
      <div class="cluster-hub-stat"><span class="cluster-hub-stat-val">${stats.regions}</span><span class="cluster-hub-stat-label">регионов</span></div>
      <div class="cluster-hub-stat"><span class="cluster-hub-stat-val">${stats.entities}</span><span class="cluster-hub-stat-label">общих токенов</span></div>
    </div>
    <h4>Общие токены</h4>
    <div class="cluster-tokens">${tokens.map(t => `<span class="cluster-token-pill">${escapeHtml(t)}</span>`).join('')}</div>
    <h4>Связанные дела</h4>
    <div class="table-scroll"><table class="data-table"><thead><tr><th>Дело</th><th>Регион</th><th>Статья</th></tr></thead><tbody>
      ${cases.map(c => `<tr><td><button type="button" class="case-link" onclick="closeClusterHub();openCase('${c.id}')">${c.id}</button></td>
        <td>${escapeHtml(c.region)}</td><td>${escapeHtml(c.article.replace(' УК РФ', ''))}</td></tr>`).join('')}
    </tbody></table></div>
    ${timeline.length ? `<h4>Лента событий (межрегион)</h4><ul class="cluster-timeline">${timeline.map(e =>
      `<li><span class="cluster-timeline-date">${escapeHtml(e.at)} · ${escapeHtml(e.region)}</span>${escapeHtml(e.text)}</li>`
    ).join('')}</ul>` : ''}
    <h4>Сравнение дел</h4>
    <div class="cluster-compare-toolbar">
      <label class="field"><span>Дело A</span>
        <select id="cluster-compare-a" onchange="updateClusterCaseCompare()">${cases.map(c => `<option value="${c.id}" ${c.id === compareA ? 'selected' : ''}>${c.id}</option>`).join('')}</select>
      </label>
      <label class="field"><span>Дело B</span>
        <select id="cluster-compare-b" onchange="updateClusterCaseCompare()">${cases.map(c => `<option value="${c.id}" ${c.id === compareB ? 'selected' : ''}>${c.id}</option>`).join('')}</select>
      </label>
    </div>
    <div id="cluster-compare-host" class="cluster-compare-host">${compareA && compareB && compareA !== compareB ? renderClusterCaseCompare(compareA, compareB) : '<p class="muted">Выберите два разных дела кластера</p>'}</div>`;
}

function openClusterHub(clusterId = 'МВ-2847') {
  activeClusterHubId = clusterId;
  syncAppDeepLinkHash({ clusterId });
  const modal = document.getElementById('cluster-hub-modal');
  const title = document.getElementById('cluster-hub-title');
  const body = document.getElementById('cluster-hub-body');
  if (!modal || !body) return;
  if (title) title.textContent = `Кластер ${clusterId}`;
  body.innerHTML = renderClusterHubPanel(clusterId);
  modal.classList.remove('hidden');
  document.body.classList.add('cluster-hub-open');
  pushAuditEntry('Просмотр кластера', clusterId, 'ПОЛ-007');
}

function closeClusterHub() {
  document.getElementById('cluster-hub-modal')?.classList.add('hidden');
  document.body.classList.remove('cluster-hub-open');
}

function downloadClusterSummary(clusterId = activeClusterHubId) {
  const cases = getClusterCases(clusterId);
  const stats = getClusterEntityCount(clusterId);
  const tokens = CLUSTER_SHARED_TOKENS[clusterId] || [];
  const timeline = CLUSTER_TIMELINE_EVENTS[clusterId] || [];
  const body = `ЕПСОК · СВОДКА КЛАСТЕРА ${clusterId}
================================
Дел в реестре:     ${stats.cases}
Регионов:          ${stats.regions}
Общих токенов:     ${stats.entities}

ОБЩИЕ ТОКЕНЫ
${tokens.map(t => `  · ${t}`).join('\n')}

ДЕЛА
${cases.map(c => `  · ${c.id} · ${c.region} · ${c.article} · ${c.lead}`).join('\n')}

ЛЕНТА СОБЫТИЙ
${timeline.map(e => `  ${e.at} · ${e.region} — ${e.text}`).join('\n')}

---
Сформировано: ${formatAuditTimestamp()} · ЕПСОК
ПОЛ-007 · обезличенная сводка · не раскрывает персональные данные
`;
  downloadTextFile(`EPSOK-cluster-${clusterId.replace(/[^A-Za-zА-Яа-я0-9-]/g, '')}.txt`, body);
  pushAuditEntry('Сводка кластера', clusterId, 'ПОЛ-007');
  showToast(`Сводка кластера ${clusterId} сохранена`);
}

const EVIDENCE_CUSTODY_SEED = {
  'ЕПСОК-2028-004521': [
    {
      id: 'EVD-004521-01',
      description: 'Ноутбук Lenovo ThinkPad · изъят при обыске',
      seizedAt: '10.02.2028',
      hash: 'a7f3e2b91c4d8056f1a9e3b7c2d8e4f6a1b3c5d7e9f0a2b4c6d8e0f1a3b5c7',
      chain: [
        { at: '10.02.2028 14:30', actor: 'Иванов С.П.', action: 'Изъятие · акт №47', to: 'Камера хранения СО №3' },
        { at: '12.06.2028 09:00', actor: 'Камера хранения СО №3', action: 'Выдача следователю', to: 'Иванов С.П.' }
      ]
    },
    {
      id: 'EVD-004521-02',
      description: 'USB-накопитель SanDisk 64 ГБ · рабочий стол подозреваемого',
      seizedAt: '10.02.2028',
      hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      chain: [
        { at: '10.02.2028 14:35', actor: 'Иванов С.П.', action: 'Изъятие · акт №47', to: 'Камера хранения СО №3' }
      ]
    },
    {
      id: 'EVD-004521-03',
      description: 'Образ диска ноутбука · forensic copy',
      seizedAt: '11.02.2028',
      hash: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
      chain: [
        { at: '11.02.2028 10:00', actor: 'ЦЭК МВД · ЮФО', action: 'Создание образа', to: 'Хранилище ЦЭК' },
        { at: '12.06.2028 09:14', actor: 'Хранилище ЦЭК', action: 'Выгрузка для OSINT', to: 'Контур открытых источников' }
      ]
    }
  ]
};

let evidenceCustodyState = {};

function loadEvidenceCustody() {
  try {
    const stored = JSON.parse(localStorage.getItem(EVIDENCE_CUSTODY_STORAGE) || '{}');
    evidenceCustodyState = { ...JSON.parse(JSON.stringify(EVIDENCE_CUSTODY_SEED)), ...stored };
  } catch {
    evidenceCustodyState = JSON.parse(JSON.stringify(EVIDENCE_CUSTODY_SEED));
  }
  Object.keys(EVIDENCE_CUSTODY_SEED).forEach(caseId => {
    if (!evidenceCustodyState[caseId]) {
      evidenceCustodyState[caseId] = JSON.parse(JSON.stringify(EVIDENCE_CUSTODY_SEED[caseId]));
    }
  });
}

function saveEvidenceCustody() {
  try { localStorage.setItem(EVIDENCE_CUSTODY_STORAGE, JSON.stringify(evidenceCustodyState)); } catch { /* demo */ }
}

function getCaseEvidenceItems(caseId) {
  const stored = evidenceCustodyState[caseId];
  if (stored?.length) return stored;
  return EVIDENCE_CUSTODY_SEED[caseId] || [];
}

function ensureCaseEvidenceCustody(caseId) {
  if (getCaseEvidenceItems(caseId).length) return getCaseEvidenceItems(caseId);
  const template = EVIDENCE_CUSTODY_SEED['ЕПСОК-2028-004521']?.[0];
  const seeded = [{
    id: `EVD-${caseId.replace(/\D/g, '').slice(-6) || '000001'}-01`,
    description: 'Цифровой носитель · демо-запись цепочки хранения',
    seizedAt: '14.06.2028',
    hash: 'a7f3e2b91c4d8056f1a9e3b7c2d8e4f6a1b3c5d7e9f0a2b4c6d8e0f1a3b5c7',
    chain: template?.chain?.length
      ? JSON.parse(JSON.stringify(template.chain))
      : [{ at: formatAuditTimestamp(), actor: getActivePersona().name, action: 'Регистрация в журнале', to: 'Камера хранения СО' }]
  }];
  evidenceCustodyState[caseId] = seeded;
  saveEvidenceCustody();
  return seeded;
}

function focusEvidenceCustody(caseId) {
  if (!personaCanBrowseCase(caseId)) {
    showToast('ПОЛ-001: нет доступа к делу.');
    return;
  }
  ensureCaseEvidenceCustody(caseId);
  const onCaseView = document.getElementById('view-case')?.classList.contains('active') && activeCaseId === caseId;
  if (!onCaseView) {
    openCase(caseId);
    setTimeout(() => scrollToEvidenceCustodyPanel(), 200);
    return;
  }
  renderCaseDetail(caseId);
  setTimeout(() => scrollToEvidenceCustodyPanel(), 50);
}

function scrollToEvidenceCustodyPanel() {
  const panel = document.querySelector('.evidence-custody-panel');
  if (panel) {
    panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
    panel.classList.add('evidence-custody-highlight');
    setTimeout(() => panel.classList.remove('evidence-custody-highlight'), 1600);
    return;
  }
  showToast('Блок цепочки хранения не найден на карточке дела.');
}

function scrollToCaseProvenance() {
  document.querySelector('.case-provenance-panel')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function addEvidenceCustodyEntry(caseId, evidenceId, action, actor) {
  const items = getCaseEvidenceItems(caseId);
  const item = items.find(e => e.id === evidenceId);
  if (!item) return;
  if (!item.chain) item.chain = [];
  const p = getActivePersona();
  item.chain.push({
    at: formatAuditTimestamp(),
    actor: actor || p.name,
    action,
    to: 'Журнал экспорта ЕПСОК'
  });
  if (!evidenceCustodyState[caseId]) evidenceCustodyState[caseId] = items;
  saveEvidenceCustody();
}

function addEvidenceCustodyExportEntries(caseId, actionLabel) {
  getCaseEvidenceItems(caseId).forEach(ev => addEvidenceCustodyEntry(caseId, ev.id, actionLabel));
}

function renderCaseEvidenceCustodySection(c) {
  const items = getCaseEvidenceItems(c.id);
  if (!items.length) return '';
  const rows = items.map(ev => `
    <tr>
      <td class="mono">${escapeHtml(ev.id)}</td>
      <td>${escapeHtml(ev.description)}</td>
      <td>${escapeHtml(ev.seizedAt)}</td>
      <td class="evidence-custody-hash">${escapeHtml(ev.hash)}</td>
      <td>
        <ul class="evidence-custody-chain">${(ev.chain || []).map(ch =>
          `<li><strong>${escapeHtml(ch.at)}</strong> · ${escapeHtml(ch.actor)} → ${escapeHtml(ch.to || '—')}: ${escapeHtml(ch.action)}</li>`
        ).join('')}</ul>
        <button type="button" class="link-btn btn-sm" onclick="scrollToCaseProvenance()">Цепочка происхождения ↓</button>
      </td>
    </tr>`).join('');
  return `<div class="panel evidence-custody-panel">
    <div class="panel-header">
      <h2>Цепочка хранения цифровых доказательств</h2>
      <div class="panel-header-actions">
        <button type="button" class="btn-sm" onclick="downloadEvidenceCustodyTxt('${c.id}')">TXT</button>
        <button type="button" class="btn-sm" onclick="copyEvidenceCustodyHashes('${c.id}')" title="Копировать хеши">⎘ SHA</button>
      </div>
    </div>
    <p class="muted">Демо-реестр изъятий · SHA-256 · запись при каждом экспорте (ПОЛ-004)</p>
    <div class="table-scroll"><table class="data-table evidence-custody-table"><thead><tr>
      <th>ID</th><th>Описание</th><th>Изъято</th><th>SHA-256</th><th>Цепочка передачи</th>
    </tr></thead><tbody>${rows}</tbody></table></div>
  </div>`;
}

const VICTIM_NOTIFICATIONS_SEED = {
  'ЕПСОК-2028-004521': [
    {
      id: 'VN-004521-01',
      at: '18.05.2028 11:20',
      channel: 'СМС',
      recipient: 'Потерпевший №12 (маск.)',
      message: 'Уведомление о принятом процессуальном решении · ст. 141 УПК РФ',
      status: 'delivered',
      actor: 'Иванов С.П.'
    },
    {
      id: 'VN-004521-02',
      at: '02.06.2028 16:45',
      channel: 'Госуслуги',
      recipient: 'Потерпевший №7 (маск.)',
      message: 'Направлено уведомление о ходе расследования · право на ознакомление',
      status: 'read',
      actor: 'Иванов С.П.'
    }
  ]
};

let victimNotificationsState = {};

function loadVictimNotifications() {
  try {
    const stored = JSON.parse(localStorage.getItem(VICTIM_NOTIFICATIONS_STORAGE) || '{}');
    victimNotificationsState = { ...JSON.parse(JSON.stringify(VICTIM_NOTIFICATIONS_SEED)), ...stored };
  } catch {
    victimNotificationsState = JSON.parse(JSON.stringify(VICTIM_NOTIFICATIONS_SEED));
  }
  Object.keys(VICTIM_NOTIFICATIONS_SEED).forEach(caseId => {
    if (!victimNotificationsState[caseId]) {
      victimNotificationsState[caseId] = JSON.parse(JSON.stringify(VICTIM_NOTIFICATIONS_SEED[caseId]));
    }
  });
}

function saveVictimNotifications() {
  try { localStorage.setItem(VICTIM_NOTIFICATIONS_STORAGE, JSON.stringify(victimNotificationsState)); } catch { /* demo */ }
}

function getVictimNotifications(caseId) {
  return victimNotificationsState[caseId] || VICTIM_NOTIFICATIONS_SEED[caseId] || [];
}

function logVictimNotification(caseId, { victim, channel, text } = {}) {
  const id = caseId || document.getElementById('victim-notif-case-id')?.value;
  const who = victim || document.getElementById('victim-notif-name')?.value?.trim();
  const ch = channel || document.getElementById('victim-notif-channel')?.value || 'Лично';
  const msg = text || document.getElementById('victim-notif-text')?.value?.trim();
  if (!id || !who || !msg || msg.length < 8) {
    showToast('Укажите потерпевшего и текст уведомления (не короче 8 символов).');
    return null;
  }
  const p = getActivePersona();
  const entry = {
    id: `VN-${Date.now()}`,
    at: formatAuditTimestamp(),
    recipient: who,
    message: msg,
    channel: ch,
    status: 'sent',
    actor: p.name
  };
  if (!victimNotificationsState[id]) victimNotificationsState[id] = getVictimNotifications(id).slice();
  victimNotificationsState[id].unshift(entry);
  saveVictimNotifications();
  appendCaseTimelineEntry(id, `Уведомление потерпевшему (${ch}): ${who}`);
  pushCaseProvenance(id, { type: 'victim', source: 'Уведомление потерпевшего', detail: `${who} · ${ch} · ${msg.slice(0, 80)}`, policy: 'ПОЛ-004' });
  pushAuditEntry('Уведомление потерпевшего', `${id} · ${who}`, 'ПОЛ-004');
  closeVictimNotificationModal();
  if (activeCaseId === id) renderCaseDetail(id);
  showToast('Уведомление зафиксировано в ленте и provenance');
  return entry;
}

function openVictimNotificationModal(caseId) {
  const c = getCaseById(caseId);
  if (!c || !personaCanAccessCase(caseId)) {
    showToast('ПОЛ-001: нет доступа к уведомлениям по делу.');
    return;
  }
  activeVictimNotificationCaseId = caseId;
  document.getElementById('victim-notif-case-id').value = caseId;
  const victimInput = document.getElementById('victim-notif-name');
  const textInput = document.getElementById('victim-notif-text');
  if (victimInput) victimInput.value = c.victims?.[0]?.name || '';
  if (textInput) textInput.value = '';
  document.getElementById('victim-notification-modal')?.classList.remove('hidden');
}

function closeVictimNotificationModal() {
  activeVictimNotificationCaseId = null;
  document.getElementById('victim-notification-modal')?.classList.add('hidden');
}

function confirmVictimNotification() {
  logVictimNotification();
}

function loadCaseBookmarks() {
  try { return JSON.parse(localStorage.getItem(BOOKMARKS_STORAGE) || '[]'); }
  catch { return []; }
}

function saveCaseBookmarks(ids) {
  try { localStorage.setItem(BOOKMARKS_STORAGE, JSON.stringify(ids)); } catch { /* demo */ }
}

function isCaseBookmarked(caseId) {
  return loadCaseBookmarks().includes(caseId);
}

function toggleCaseBookmark(caseId, ev) {
  ev?.stopPropagation?.();
  const bookmarks = loadCaseBookmarks();
  const idx = bookmarks.indexOf(caseId);
  if (idx >= 0) bookmarks.splice(idx, 1);
  else bookmarks.push(caseId);
  saveCaseBookmarks(bookmarks);
  showToast(idx >= 0 ? 'Удалено из избранного' : 'Дело добавлено в избранное');
  if (document.getElementById('view-cases')?.classList.contains('active')) renderCasesRegistry();
  if (activeCaseId === caseId) renderCaseDetail(caseId);
}

function getFiltersStorageKey(base) {
  const pid = getActivePersona()?.id || 'anon';
  return `${base}:${pid}`;
}

function saveCasesFiltersState() {
  try {
    localStorage.setItem(getFiltersStorageKey(CASES_FILTERS_STORAGE), JSON.stringify({
      scope: caseFilterScope,
      bookmark: casesBookmarkFilter,
      search: casesSearchQuery,
      status: casesStatusFilter
    }));
  } catch { /* noop */ }
}

function loadCasesFiltersState() {
  try {
    const raw = localStorage.getItem(getFiltersStorageKey(CASES_FILTERS_STORAGE));
    if (!raw) return false;
    const data = JSON.parse(raw);
    if (data.scope) caseFilterScope = data.scope;
    casesBookmarkFilter = !!data.bookmark;
    casesSearchQuery = data.search || '';
    casesStatusFilter = data.status || 'all';
    return true;
  } catch {
    return false;
  }
}

function saveRequestsFiltersState() {
  try {
    localStorage.setItem(getFiltersStorageKey(REQUESTS_FILTERS_STORAGE), JSON.stringify({
      scope: requestFilterScope,
      status: requestStatusFilter
    }));
  } catch { /* noop */ }
}

function loadRequestsFiltersState() {
  try {
    const raw = localStorage.getItem(getFiltersStorageKey(REQUESTS_FILTERS_STORAGE));
    if (!raw) return;
    const data = JSON.parse(raw);
    if (data.scope) requestFilterScope = data.scope;
    if (data.status) requestStatusFilter = data.status;
  } catch { /* noop */ }
}

function setCasesRegistrySearch(query) {
  casesSearchQuery = query;
  resetTablePage('cases');
  saveCasesFiltersState();
  renderCasesRegistry();
}

function setCasesStatusFilter(status) {
  casesStatusFilter = status;
  resetTablePage('cases');
  saveCasesFiltersState();
  renderCasesRegistry();
}

function toggleCasesBookmarkFilter() {
  casesBookmarkFilter = !casesBookmarkFilter;
  resetTablePage('cases');
  saveCasesFiltersState();
  renderCasesRegistry();
}

function renderCaseBookmarkBtn(caseId) {
  const active = isCaseBookmarked(caseId);
  return `<button type="button" class="case-bookmark-btn${active ? ' active' : ''}" onclick="toggleCaseBookmark('${caseId}', event)" title="${active ? 'Убрать из избранного' : 'В избранное'}" aria-label="Избранное">★</button>`;
}

function getDemoCertFingerprint(p = getActivePersona()) {
  const cert = getPresence(p?.id)?.cert || 'ESIA-DEMO';
  const hash = cert.split('').reduce((a, ch) => ((a << 5) - a) + ch.charCodeAt(0), 0);
  const hex = Math.abs(hash).toString(16).toUpperCase().padStart(8, '0');
  return `${hex.slice(0, 2)}:${hex.slice(2, 4)}…${hex.slice(4, 8)}`;
}

function appendDemoExportSignatureBlock(body) {
  const p = getActivePersona();
  return `${body}
ЭЛЕКТРОННАЯ ПОДПИСЬ (ДЕМО)
ЭП подпись: СПЕКТР-256 (демо)
Подписант:     ${p?.name || '—'}
Сертификат:    ${getPresence(p?.id)?.cert || 'ESIA-DEMO'}
Отпечаток:     ${getDemoCertFingerprint(p)}
Время:         ${formatAuditTimestamp()}
`;
}

function toggleDeadlinesViewMode(mode) {
  deadlinesViewMode = mode === 'calendar' ? 'calendar' : 'list';
  renderDeadlines();
}

function renderDeadlinesCalendar() {
  const cases = getDeadlinesCaseList();
  const now = getDemoNow();
  const year = now.getFullYear();
  const month = now.getMonth();
  const firstDow = (new Date(year, month, 1).getDay() + 6) % 7;
  const daysInMonth = new Date(year, month + 1, 0).getDate();
  const monthLabel = now.toLocaleDateString('ru-RU', { month: 'long', year: 'numeric' });
  const byDay = new Map();
  cases.forEach(c => {
    if (c.daysLeft == null) return;
    const due = new Date(now.getTime() + c.daysLeft * 86400000);
    if (due.getMonth() !== month || due.getFullYear() !== year) return;
    const day = due.getDate();
    if (!byDay.has(day)) byDay.set(day, []);
    byDay.get(day).push(c);
  });
  const weekdays = ['Пн', 'Вт', 'Ср', 'Чт', 'Пт', 'Сб', 'Вс'];
  let cells = '';
  for (let i = 0; i < firstDow; i++) cells += '<div class="dl-cal-cell dl-cal-cell--empty"></div>';
  for (let d = 1; d <= daysInMonth; d++) {
    const list = byDay.get(d) || [];
    const worst = list.reduce((w, c) => {
      if (c.daysLeft <= 3) return 'critical';
      if (c.daysLeft <= 7 && w !== 'critical') return 'warning';
      return w;
    }, '');
    const dots = list.map(c => {
      const lvl = c.daysLeft <= 3 ? 'critical' : c.daysLeft <= 7 ? 'warning' : 'ok';
      return `<span class="dl-cal-dot dl-cal-dot--${lvl}" title="${escapeHtml(c.id)}"></span>`;
    }).join('');
    const isToday = d === now.getDate();
    cells += `<div class="dl-cal-cell${isToday ? ' dl-cal-cell--today' : ''}${worst ? ` dl-cal-cell--${worst}` : ''}">
      <span class="dl-cal-day">${d}</span>${dots ? `<div class="dl-cal-dots">${dots}</div>` : ''}
    </div>`;
  }
  return `<div class="deadlines-calendar panel">
    <h2>Календарь сроков · ${escapeHtml(monthLabel)}</h2>
    <p class="muted deadlines-cal-hint">Точки — ключевые сроки дел вашего контура · клик по делу в списке ниже</p>
    <div class="dl-cal-weekdays">${weekdays.map(w => `<span>${w}</span>`).join('')}</div>
    <div class="dl-cal-grid">${cells}</div>
    <div class="dl-cal-legend">
      <span><i class="dl-cal-dot dl-cal-dot--critical"></i> ≤3 дн.</span>
      <span><i class="dl-cal-dot dl-cal-dot--warning"></i> ≤7 дн.</span>
      <span><i class="dl-cal-dot dl-cal-dot--ok"></i> норма</span>
    </div>
  </div>`;
}

function loadWitnessProtection() {
  try { return JSON.parse(localStorage.getItem(WITNESS_PROTECTION_STORAGE) || '{}'); }
  catch { return {}; }
}

function saveWitnessProtection(state) {
  try { localStorage.setItem(WITNESS_PROTECTION_STORAGE, JSON.stringify(state)); } catch { /* demo */ }
}

function isSuspectWitnessProtected(suspectId) {
  return !!loadWitnessProtection()[suspectId];
}

function toggleWitnessProtection(suspectId) {
  const s = suspectDossiers.find(x => x.id === suspectId);
  if (!s || !canEditSuspectDossier(s)) {
    showToast('ПОЛ-009: изменение режима защиты недоступно.');
    return;
  }
  const state = loadWitnessProtection();
  if (state[suspectId]) delete state[suspectId];
  else state[suspectId] = { at: formatAuditTimestamp(), by: getActivePersona().name };
  saveWitnessProtection(state);
  pushAuditEntry('Особая защита фигуранта', `${suspectId} · ${state[suspectId] ? 'включена' : 'снята'}`, 'ПОЛ-009');
  renderSuspects();
  showToast(state[suspectId] ? 'Режим «Особая защита» включён (ПОЛ-009)' : 'Режим «Особая защита» снят');
}

function renderAdminIntegrationHealthPanel() {
  if (!canViewSystemInternals()) return '';
  const pills = [
    { id: 'SMEV', label: 'СМЭВ', status: 'online', note: 'очередь 12 · P99 840 мс' },
    { id: 'GIS', label: 'ГИС ГМП', status: 'online', note: 'синхронизация 14.06 08:00' },
    { id: 'GOS', label: 'Госуслуги', status: 'degraded', note: 'задержка уведомлений · SLA 6 ч' },
    { id: 'ESIA', label: 'ЕСИА', status: 'online', note: 'сертификаты · ротация 22.06' }
  ];
  return `<div class="panel admin-integration-health-panel">
    <h2>Состояние интеграций</h2>
    <p class="muted admin-integration-hint">Внешние контуры · только тех. админ ЦОД · ПОЛ-008</p>
    <div class="admin-integration-pills">${pills.map(p => `
      <div class="admin-integration-pill admin-integration-pill--${p.status}">
        <span class="admin-integration-pill-label">${escapeHtml(p.label)}</span>
        <span class="admin-integration-pill-status">${p.status === 'online' ? 'online' : 'degraded'}</span>
        <span class="admin-integration-pill-note muted">${escapeHtml(p.note)}</span>
      </div>`).join('')}
    </div>
  </div>`;
}

function loadHorizonWatchlist() {
  try { return JSON.parse(localStorage.getItem(HORIZON_WATCH_STORAGE) || '[]'); }
  catch { return []; }
}

function saveHorizonWatchlist(tokens) {
  try { localStorage.setItem(HORIZON_WATCH_STORAGE, JSON.stringify(tokens)); } catch { /* demo */ }
}

function isHorizonTokenWatched(token) {
  return loadHorizonWatchlist().includes(token);
}

function toggleHorizonWatchToken(token) {
  const list = loadHorizonWatchlist();
  const idx = list.indexOf(token);
  if (idx >= 0) list.splice(idx, 1);
  else list.push(token);
  saveHorizonWatchlist(list);
  pushAuditEntry('Watchlist «Горизонт»', token, 'ПОЛ-007');
  renderHorizon();
  showToast(idx >= 0 ? 'Токен убран из watchlist' : 'Токен добавлен в watchlist');
}

function getHorizonWatchHitCount() {
  const watch = loadHorizonWatchlist();
  if (!watch.length) return 0;
  const profile = getHorizonProfile(activeHorizonCaseId);
  const col = profile.collision?.caseToken;
  const ghost = (profile.ghostPath || []).map(n => n.label).join(' ');
  const hits = watch.filter(t => (col && col.includes(t)) || ghost.includes(t) || (CLUSTER_SHARED_TOKENS[profile.cluster] || []).some(x => x.includes(t)));
  return hits.length;
}

function renderHorizonWatchTokenBtn(token) {
  const active = isHorizonTokenWatched(token);
  const safe = token.replace(/'/g, "\\'");
  return `<button type="button" class="btn-sm horizon-watch-token-btn${active ? ' active' : ''}" onclick="toggleHorizonWatchToken('${safe}')" title="${active ? 'Убрать из watchlist' : 'Добавить в watchlist'}">${active ? '★' : '☆'} ${escapeHtml(token)}</button>`;
}

function renderHorizonWatchlistPanel() {
  const profile = getHorizonProfile(activeHorizonCaseId);
  const watch = loadHorizonWatchlist();
  const suggested = [...new Set([
    profile.collision?.caseToken,
    ...(CLUSTER_SHARED_TOKENS[profile.cluster] || [])
  ].filter(Boolean))];
  return `<div class="panel horizon-watch-panel">
    <div class="panel-header"><h2>Watchlist токенов</h2>
      <div class="panel-header-actions">
        ${renderHorizonWatchBadge()}
        <button type="button" class="btn-sm" onclick="exportHorizonWatchlistTxt()">TXT</button>
      </div>
    </div>
    <p class="muted horizon-watch-hint">localStorage · сигнал при совпадении в коллизии или ghost-пути</p>
    <div class="horizon-watch-suggested">${suggested.map(t => renderHorizonWatchTokenBtn(t)).join('')}</div>
    ${watch.length ? `<p class="horizon-watch-active muted">Активно: ${watch.map(t => escapeHtml(t)).join(' · ')}</p>` : '<p class="muted">Добавьте токен из списка выше</p>'}
  </div>`;
}

function renderHorizonWatchBadge() {
  const n = getHorizonWatchHitCount();
  if (!n) return '';
  return `<span class="horizon-watch-badge" title="Совпадение с watchlist">${n} в watchlist</span>`;
}

function canChangeCaseStatus(p = getActivePersona()) {
  return hasLeadCapabilities(p) && canAccessView('cases', p);
}

const DEMO_CASE_STATUS_CHANGES = {
  suspended: { status: 'suspended', label: 'Приостановить', stage: 'Следствие', timeline: 'Дело приостановлено (демо) · ст. 208 УПК' },
  merged: { status: 'merged', label: 'Объединить', stage: 'Следствие', timeline: 'Постановление об объединении дел (демо)' },
  closed: { status: 'closed', label: 'Закрыть', stage: 'Завершено', timeline: 'Производство прекращено / направлено в суд (демо)' }
};

function openCaseStatusChangeModal(caseId, action) {
  const cfg = DEMO_CASE_STATUS_CHANGES[action];
  if (!cfg || !canChangeCaseStatus()) return;
  pendingCaseStatusChange = { caseId, action };
  const c = getCaseById(caseId);
  const title = document.getElementById('case-status-modal-title');
  const hint = document.getElementById('case-status-modal-hint');
  if (title) title.textContent = `${cfg.label} · ${caseId}`;
  if (hint) hint.textContent = `${c?.article || ''} · текущий статус: ${caseStatusLabels[c?.status] || c?.status} → ${cfg.label.toLowerCase()}`;
  document.getElementById('case-status-modal')?.classList.remove('hidden');
}

function closeCaseStatusChangeModal() {
  pendingCaseStatusChange = null;
  document.getElementById('case-status-modal')?.classList.add('hidden');
}

function confirmCaseStatusChange() {
  if (!pendingCaseStatusChange) return;
  const { caseId, action } = pendingCaseStatusChange;
  const cfg = DEMO_CASE_STATUS_CHANGES[action];
  const c = getCaseById(caseId);
  if (!c || !cfg) return;
  c.status = cfg.status;
  if (cfg.stage) c.stage = cfg.stage;
  if (action === 'suspended') c.daysLeft = null;
  appendCaseTimelineEntry(caseId, cfg.timeline);
  pushCaseProvenance(caseId, { type: 'status', source: 'Статус дела', detail: cfg.timeline, policy: 'ПОЛ-004' });
  pushAuditEntry('Изменение статуса дела', `${caseId} → ${cfg.label}`, 'ПОЛ-004');
  closeCaseStatusChangeModal();
  renderCaseDetail(caseId);
  if (document.getElementById('view-cases')?.classList.contains('active')) renderCasesRegistry();
  showToast(`Статус дела обновлён: ${cfg.label}`);
}

function renderCaseStatusWorkflowHtml(caseId) {
  if (!canChangeCaseStatus()) return '';
  return `<div class="case-status-workflow">
    <label class="field case-status-field">
      <span>Статус</span>
      <select id="case-status-select" onchange="openCaseStatusChangeModal('${caseId}', this.value);this.value=''">
        <option value="">Изменить…</option>
        <option value="suspended">Приостановить</option>
        <option value="merged">Объединить</option>
        <option value="closed">Закрыть</option>
      </select>
    </label>
  </div>`;
}

function openBatchRequestWizard(caseId) {
  const c = getCaseById(caseId);
  if (!c || !canCreateRequest()) {
    showToast('ПОЛ-003: создание пакета запросов недоступно.');
    return;
  }
  document.getElementById('batch-request-case-id').value = caseId;
  document.getElementById('batch-req-fns').checked = true;
  document.getElementById('batch-req-rfm').checked = true;
  document.getElementById('batch-req-mvd').checked = true;
  const legal = document.getElementById('batch-req-legal');
  if (legal) legal.value = c.legalBasis || `Постановление следователя по делу ${c.id}`;
  document.getElementById('batch-request-modal')?.classList.remove('hidden');
}

function closeBatchRequestWizard() {
  document.getElementById('batch-request-modal')?.classList.add('hidden');
}

function confirmBatchRequestWizard() {
  const caseId = document.getElementById('batch-request-case-id')?.value;
  const legal = document.getElementById('batch-req-legal')?.value?.trim();
  if (!caseId || !legal) {
    showToast('Укажите правовое основание для пакета запросов.');
    return;
  }
  const picks = [
    { id: 'batch-req-fns', agency: 'FNS', type: '2-НДФЛ', label: 'ФНС · 2-НДФЛ' },
    { id: 'batch-req-rfm', agency: 'RFM', type: 'movement', label: 'РФМ · движение средств' },
    { id: 'batch-req-mvd', agency: 'MVD', type: 'cdr', label: 'МВД · CDR' }
  ].filter(p => document.getElementById(p.id)?.checked);
  if (!picks.length) {
    showToast('Выберите хотя бы один запрос в пакете.');
    return;
  }
  picks.forEach((p, i) => {
    setTimeout(() => {
      openNewRequestModal('interagency', p.agency, p.type, {
        subject: `Дело ${caseId}`,
        legal,
        skipTemplateReset: true
      });
      const title = document.getElementById('request-modal-title');
      if (title) title.textContent = `Пакет ${i + 1}/${picks.length} · ${p.label}`;
    }, i * 120);
  });
  pushAuditEntry('Пакет межвед. запросов', `${caseId} · ${picks.length} черновик(ов)`, 'ПОЛ-003');
  closeBatchRequestWizard();
  showToast(`Создано ${picks.length} черновик(ов) · проверьте и отправьте`);
}

function buildGraphAdjacency(caseId) {
  const ids = new Set(graphNodes.filter(n => n.caseId === caseId).map(n => n.id));
  const adj = new Map();
  ids.forEach(id => adj.set(id, []));
  graphEdges.forEach(([a, b]) => {
    if (!ids.has(a) || !ids.has(b)) return;
    adj.get(a).push(b);
    adj.get(b).push(a);
  });
  return adj;
}

function findGraphPathBfs(caseId, startId, endId) {
  if (startId === endId) return { nodes: [startId], edges: [] };
  const adj = buildGraphAdjacency(caseId);
  const prev = new Map();
  const q = [startId];
  prev.set(startId, null);
  while (q.length) {
    const cur = q.shift();
    for (const nb of adj.get(cur) || []) {
      if (prev.has(nb)) continue;
      prev.set(nb, cur);
      if (nb === endId) {
        const nodes = [];
        let x = endId;
        while (x) { nodes.unshift(x); x = prev.get(x); }
        const edges = [];
        for (let i = 0; i < nodes.length - 1; i++) edges.push([nodes[i], nodes[i + 1]]);
        return { nodes, edges };
      }
      q.push(nb);
    }
  }
  return null;
}

function toggleGraphPathPick(nodeId) {
  if (!nodeId) return;
  const idx = graphPathState.picks.indexOf(nodeId);
  if (idx >= 0) graphPathState.picks.splice(idx, 1);
  else {
    if (graphPathState.picks.length >= 2) graphPathState.picks.shift();
    graphPathState.picks.push(nodeId);
  }
  updateGraphPathPanel();
  graphView?.renderPathState?.();
}

function addGraphPathPickFromSelection(nodeId) {
  const id = nodeId || graphDetailNodeId;
  if (!id) {
    showToast('Сначала выберите узел на графе.');
    return;
  }
  if (graphPathState.picks.includes(id)) {
    showToast('Узел уже в списке для поиска пути.');
    return;
  }
  if (graphPathState.picks.length >= 2) graphPathState.picks.shift();
  graphPathState.picks.push(id);
  updateGraphPathPanel();
  graphView?.renderPathState?.();
  showToast(graphPathState.picks.length === 2 ? 'Два узла выбраны · можно искать путь' : 'Узел добавлен · выберите второй');
}

function runGraphPathFinder() {
  if (graphPathState.picks.length !== 2) {
    showToast('Выберите ровно 2 узла на графе.');
    return;
  }
  const [a, b] = graphPathState.picks;
  const path = findGraphPathBfs(activeGraphCaseId, a, b);
  if (!path) {
    graphPathState.pathNodeIds = null;
    graphPathState.pathEdges = null;
    showToast('Путь между узлами не найден.');
  } else {
    graphPathState.pathNodeIds = path.nodes;
    graphPathState.pathEdges = path.edges;
    showToast(`Путь найден · ${path.nodes.length} узл. · ${path.edges.length} ребёр`);
  }
  updateGraphPathPanel();
  graphView?.renderPathState?.();
}

function clearGraphPathFinder() {
  graphPathState.picks = [];
  graphPathState.pathNodeIds = null;
  graphPathState.pathEdges = null;
  updateGraphPathPanel();
  graphView?.renderPathState?.();
}

function updateGraphPathPanel() {
  const el = document.getElementById('graph-path-panel');
  if (!el) return;
  const labels = graphPathState.picks.map(id => {
    const n = graphNodes.find(x => x.id === id);
    return n ? getGraphCanvasLabel(n) : id;
  });
  const pathList = graphPathState.pathNodeIds?.map((id, i) => {
    const n = graphNodes.find(x => x.id === id);
    return `<li><span class="graph-path-hop-num">${i + 1}</span>${escapeHtml(n ? getGraphCanvasLabel(n) : id)}</li>`;
  }).join('') || '';
  const canAddCurrent = !!graphDetailNodeId && !graphPathState.picks.includes(graphDetailNodeId);
  const canRun = graphPathState.picks.length === 2;
  el.innerHTML = `
    <h3>Поиск пути</h3>
    <p class="muted graph-path-hint">Shift+клик или Alt+клик по узлам · или «+ Текущий»</p>
    <p class="graph-path-picks">${labels.length ? labels.map(l => `<span class="link-badge">${escapeHtml(l)}</span>`).join(' → ') : '<span class="muted">Узлы не выбраны</span>'}</p>
    <div class="graph-path-actions">
      <button type="button" class="btn-sm" onclick="addGraphPathPickFromSelection()" ${canAddCurrent ? '' : 'disabled'} title="Добавить выбранный на графе узел">+ Текущий</button>
      <button type="button" class="btn-sm btn-primary" onclick="runGraphPathFinder()" ${canRun ? '' : 'disabled'}>Найти путь</button>
      <button type="button" class="btn-sm" onclick="clearGraphPathFinder()">Сбросить</button>
    </div>
    ${pathList ? `<ol class="graph-path-hop-list">${pathList}</ol>
    <div class="graph-path-export-actions">
      <button type="button" class="btn-sm" onclick="copyGraphPathReport()">Копировать</button>
      <button type="button" class="btn-sm" onclick="downloadGraphPathReportTxt()">Отчёт (TXT)</button>
    </div>` : ''}`;
}

function buildCaseActivityFeed(caseId) {
  const c = getCaseById(caseId);
  if (!c) return [];
  const items = [];

  (c.timeline || []).forEach(t => {
    items.push({
      at: t.date,
      kind: 'timeline',
      filter: 'все',
      icon: '📅',
      title: 'Хронология',
      text: t.text,
      highlight: t.highlight
    });
  });

  getCaseRelatedRequests(caseId).forEach(r => {
    items.push({
      at: r.sent || r.fulfilledAt || '—',
      kind: 'request',
      filter: 'запросы',
      icon: '⇄',
      title: r.id,
      text: `${r.type} · ${r.target || '—'} · ${requestStatusLabels[r.status] || r.status}`,
      actor: r.from
    });
  });

  getCaseProvenance(caseId).forEach(p => {
    const evidence = p.type === 'export' || /custody|доказатель|изъят|образ/i.test(p.detail || '');
    items.push({
      at: p.at,
      kind: 'provenance',
      filter: evidence ? 'доказательства' : 'все',
      icon: '⛓',
      title: p.source,
      text: p.detail,
      actor: p.actor
    });
  });

  getCaseEvidenceItems(caseId).forEach(ev => {
    (ev.chain || []).forEach(ch => {
      items.push({
        at: ch.at,
        kind: 'custody',
        filter: 'доказательства',
        icon: '▣',
        title: ev.id,
        text: `${ch.action} · ${ch.actor} → ${ch.to || '—'}`
      });
    });
  });

  if (c.daysLeft != null && c.daysLeft <= 14) {
    items.push({
      at: formatAuditTimestamp(),
      kind: 'deadline',
      filter: 'сроки',
      icon: '⏱',
      title: 'Контроль УПК',
      text: `Осталось ${c.daysLeft} дн. · ${c.proceduralStage || c.stage}`
    });
  }

  getVictimNotifications(caseId).forEach(vn => {
    const who = vn.recipient || vn.victim || '—';
    const msg = vn.message || vn.text || '—';
    items.push({
      at: vn.at,
      kind: 'victim',
      filter: 'все',
      icon: '✉',
      title: `Уведомление · ${vn.channel}`,
      text: `${who}: ${msg}`,
      actor: vn.actor
    });
  });

  return items.sort((a, b) => {
    const ta = parseDemoDateRu(a.at)?.getTime() || 0;
    const tb = parseDemoDateRu(b.at)?.getTime() || 0;
    return tb - ta;
  });
}

function filterCaseActivityItems(items, filter) {
  if (!filter || filter === 'все') return items;
  return items.filter(it => it.filter === filter || it.kind === filter);
}

function renderCaseActivityFeed(c) {
  const feed = filterCaseActivityItems(buildCaseActivityFeed(c.id), caseActivityFilter);
  if (!feed.length) {
    return '<p class="muted activity-feed-empty">Нет событий в выбранной категории</p>';
  }
  return `<ul class="activity-feed-list">${feed.map(it => `
    <li class="activity-feed-item activity-feed-item--${escapeHtml(it.kind)}${it.highlight ? ' activity-feed-item--highlight' : ''}">
      <span class="activity-feed-icon" aria-hidden="true">${it.icon}</span>
      <div class="activity-feed-body">
        <div class="activity-feed-head">
          <strong>${escapeHtml(it.title)}</strong>
          <span class="activity-feed-time muted">${escapeHtml(it.at)}</span>
        </div>
        <p>${escapeHtml(it.text)}</p>
        ${it.actor ? `<span class="muted activity-feed-actor">${escapeHtml(it.actor)}</span>` : ''}
      </div>
    </li>`).join('')}</ul>`;
}

function setCaseActivityFilter(filter, caseId) {
  caseActivityFilter = filter;
  renderCaseDetail(caseId);
}

function renderCaseActivityFeedSection(c) {
  const chips = ['все', 'запросы', 'доказательства', 'сроки'];
  return `<div class="panel case-activity-feed-panel">
    <div class="panel-header">
      <h2>Лента событий</h2>
      <div class="panel-header-actions">
        <button type="button" class="btn-sm" onclick="downloadCaseActivityFeedTxt('${c.id}')" title="Экспорт ленты">TXT</button>
        <span class="muted activity-feed-hint">Хронология · запросы · provenance · custody · сроки</span>
      </div>
    </div>
    <div class="activity-feed-chips" role="tablist" aria-label="Фильтр ленты">
      ${chips.map(chip => `<button type="button" class="activity-feed-chip${caseActivityFilter === chip ? ' active' : ''}"
        role="tab" aria-selected="${caseActivityFilter === chip}" onclick="setCaseActivityFilter('${chip}','${c.id}')">${chip}</button>`).join('')}
    </div>
    ${renderCaseActivityFeed(c)}
  </div>`;
}

function renderCaseVictimNotificationsSection(c) {
  const items = getVictimNotifications(c.id);
  if (!items.length && !personaCanAccessCase(c.id)) return '';
  const rows = items.map(vn => {
    const who = vn.recipient || vn.victim || '—';
    const msg = vn.message || vn.text || '—';
    return `
    <tr>
      <td class="mono">${escapeHtml(vn.at)}</td>
      <td>${escapeHtml(vn.channel)}</td>
      <td>${escapeHtml(who)}</td>
      <td>${escapeHtml(msg)}</td>
      <td><span class="victim-notif-status victim-notif-status--${vn.status}">${vn.status === 'sent' ? 'направлено' : vn.status === 'pending' ? 'ожидает' : vn.status === 'read' ? 'прочитано' : 'доставлено'}</span></td>
    </tr>`;
  }).join('');
  const logBtn = personaCanAccessCase(c.id)
    ? `<button type="button" class="btn-sm" onclick="openVictimNotificationModal('${c.id}')">Зафиксировать уведомление</button>`
    : '';
  const exportBtn = items.length
    ? `<button type="button" class="btn-sm" onclick="downloadVictimNotificationsTxt('${c.id}')">TXT</button>`
    : '';
  return `<div class="panel victim-notifications-panel">
    <div class="panel-header">
      <h2>Уведомления потерпевших</h2>
      <div class="panel-header-actions">${exportBtn}${logBtn}</div>
    </div>
    <p class="muted victim-notif-hint">Регистрация уведомлений по ст. 141 УПК · запись в ленту и цепочку происхождения</p>
    ${items.length ? `<div class="table-scroll"><table class="data-table victim-notif-table"><thead><tr>
      <th>Время</th><th>Канал</th><th>Получатель</th><th>Содержание</th><th>Статус</th>
    </tr></thead><tbody>${rows}</tbody></table></div>` : '<p class="muted">Уведомлений пока нет</p>'}
  </div>`;
}

function renderDeadlineExtensionButton(caseId) {
  const c = getCaseById(caseId);
  if (!c || c.daysLeft == null || c.daysLeft > 7 || !personaCanAccessCase(caseId)) return '';
  return `<button type="button" class="btn-sm deadline-extension-btn" onclick="openDeadlineExtensionModal('${caseId}')">Ходатайство о продлении</button>`;
}

function openDeadlineExtensionModal(caseId) {
  const c = getCaseById(caseId);
  if (!c) return;
  activeDeadlineExtensionCaseId = caseId;
  const hint = document.getElementById('deadline-extension-hint');
  const grounds = document.getElementById('deadline-extension-grounds');
  const months = document.getElementById('deadline-extension-months');
  const hidden = document.getElementById('deadline-extension-case-id');
  if (hidden) hidden.value = caseId;
  if (hint) hint.textContent = `${c.id} · осталось ${c.daysLeft} дн. · ${c.article} · ст. 162 УПК РФ`;
  if (grounds) {
    const pending = getCaseRelatedRequests(caseId).filter(r => ['progress', 'submitted'].includes(r.status)).length;
    grounds.value = [
      `Дело ${c.id} · ${c.crimeType} · ${c.proceduralStage || c.stage}.`,
      `Объём следственных действий и межведомственных запросов${pending ? ` (${pending} в работе)` : ''}.`,
      'Компьютерная экспертиза в очереди ЦЭК · изъятие цифровых носителей.',
      c.cluster ? `Координация в кластере ${c.cluster}.` : ''
    ].filter(Boolean).join('\n');
  }
  if (months) months.value = c.daysLeft <= 3 ? '6' : '3';
  document.getElementById('deadline-extension-modal')?.classList.remove('hidden');
}

function closeDeadlineExtensionModal() {
  activeDeadlineExtensionCaseId = null;
  document.getElementById('deadline-extension-modal')?.classList.add('hidden');
}

function downloadDeadlineExtensionDraft(caseId) {
  const c = getCaseById(caseId || activeDeadlineExtensionCaseId);
  if (!c) return;
  const p = getActivePersona();
  const grounds = document.getElementById('deadline-extension-grounds')?.value?.trim()
    || 'Объём следственных действий · межведомственные запросы';
  const months = document.getElementById('deadline-extension-months')?.value || '3';
  const article = c.stage === 'Дознание' ? 'ст. 223 УПК РФ' : 'ст. 162 УПК РФ';
  const body = `ХОДАТАЙСТВО О ПРОДЛЕНИИ СРОКА ПРЕДВАРИТЕЛЬНОГО СЛЕДСТВИЯ
============================================
Дело:              ${c.id}
Статья:            ${c.article}
Основание:         ${article}
Следователь:       ${p.name}
Подразделение:     ${c.department}
Регион:            ${c.region}

Обоснование:
${grounds}

Запрашиваемый срок продления: ${months} мес.
Текущий остаток: ${c.daysLeft} дн.

НОРМАТИВНЫЕ ССЫЛКИ
  · ${article}
  · ст. 165 УПК РФ — порядок продления
  · ПОЛ-002 ЕПСОК — контроль сроков

---
Черновик ЕПСОК · ${formatAuditTimestamp()}
Не является процессуальным документом до подписания
`;
  const safeId = c.id.replace(/[^A-Za-zА-Яа-я0-9-]/g, '');
  downloadTextFile(`EPSOK-${safeId}-extension-draft.txt`, appendDemoExportSignatureBlock(body));
  appendCaseTimelineEntry(c.id, `Подготовлен черновик ходатайства о продлении срока (${months} мес.)`);
  pushCaseProvenance(c.id, {
    type: 'timeline',
    source: 'УПК · продление',
    detail: `Черновик ходатайства · +${months} мес.`,
    policy: 'ПОЛ-004'
  });
  pushAuditEntry('Черновик ходатайства о продлении', c.id, 'ПОЛ-002');
  closeDeadlineExtensionModal();
  if (activeCaseId === c.id) renderCaseDetail(c.id);
  if (activeDeadlinesCaseId === c.id) renderDeadlines();
  showToast(`Черновик сохранён: EPSOK-${safeId}-extension-draft.txt`);
}

function getCaseUnimportedOsintCount(caseId) {
  let count = 0;
  osintScans.filter(s => s.caseId === caseId).forEach(s => {
    (osintFindingsByScan[s.id] || []).forEach(f => { if (!f.importedToGraph) count += 1; });
  });
  return count;
}

function getCaseGraphRecommendations(caseId) {
  const recs = [];
  const c = getCaseById(caseId);
  const m = getCaseHealthMetrics(caseId);
  if (!c || !m) return recs;

  const nodes = graphNodes.filter(n => n.caseId === caseId);
  const phoneIds = nodes.filter(n => n.type === 'phone').map(n => n.id);
  const accountIds = nodes.filter(n => n.type === 'account').map(n => n.id);
  if (phoneIds.length && !accountIds.length) {
    recs.push({ id: 'sim-account-fns', text: 'нет связи счёт→SIM' });
  } else if (phoneIds.length && accountIds.length) {
    const linked = graphEdges.some(([a, b]) =>
      (phoneIds.includes(a) && accountIds.includes(b)) || (phoneIds.includes(b) && accountIds.includes(a))
    );
    if (!linked) {
      recs.push({ id: 'sim-account-rfm', text: 'нет связи счёт→SIM' });
    }
  }
  const hasFnsActive = getCaseRelatedRequests(caseId).some(r =>
    (r.target?.includes('ФНС') || r.type?.includes('2-НДФЛ') || r.type?.includes('ЕГРЮЛ')) &&
    !['fulfilled', 'rejected', 'expired', 'draft'].includes(r.status)
  );
  if (!hasFnsActive && (c.keyObjects?.some(o => o.type === 'account') || m.requestBacklog > 0)) {
    recs.push({ id: 'fns', text: 'добавить запрос ФНС' });
  }
  if (m.graphGap) {
    recs.push({ id: 'graph', text: 'Заполнить пробел графа' });
  }
  if (m.requestBacklog > 0) {
    recs.push({ id: 'requests', text: `Контроль ${m.requestBacklog} неисполненных запросов` });
  }
  if (c.daysLeft != null && c.daysLeft <= 7) {
    recs.push({ id: 'deadline', text: 'Подготовить ходатайство о продлении срока УПК' });
  }
  if (!getCaseEvidenceItems(caseId).length) {
    recs.push({ id: 'custody', text: 'Зафиксировать цепочку хранения цифровых доказательств' });
  }
  const unimported = getCaseUnimportedOsintCount(caseId);
  if (unimported > 0) {
    recs.push({ id: 'osint', text: `Импортировать ${unimported} находок OSINT в граф` });
  }
  return recs;
}

function runCaseGraphRecommendation(caseId, recId) {
  switch (recId) {
    case 'sim-account-fns':
      openNewRequestModal('interagency', 'FNS', 'FNS_ACCOUNT_INFO');
      break;
    case 'sim-account-rfm':
      openNewRequestModal('interagency', 'RFM', 'RFM_TRANSACTIONS');
      break;
    case 'fns':
      openNewRequestModal('interagency', 'FNS', 'FNS_INCOME_2NDFL');
      break;
    case 'graph':
      openCaseGraph(caseId);
      break;
    case 'requests':
      showView('requests');
      break;
    case 'deadline':
      openDeadlineExtensionModal(caseId);
      break;
    case 'custody':
      focusEvidenceCustody(caseId);
      break;
    case 'osint':
      openCaseOsint(caseId);
      break;
    default:
      showToast('Рекомендация недоступна в демо.');
  }
}

function renderCaseGraphRecommendationsHtml(caseId) {
  const recs = getCaseGraphRecommendations(caseId);
  if (!recs.length || !canAccessView('graph')) return '';
  const safeId = escapeHtml(caseId).replace(/'/g, "\\'");
  return `<div class="case-graph-recommendations" role="region" aria-label="Рекомендации графа">
    <span class="case-graph-recommendations-label">Рекомендации графа</span>
    <ul class="case-graph-recommendations-list">${recs.slice(0, 3).map(r =>
      `<li><button type="button" class="link-btn case-rec-action" onclick="runCaseGraphRecommendation('${safeId}','${r.id}')">${escapeHtml(r.text)}</button></li>`
    ).join('')}</ul>
  </div>`;
}

function renderGraphRecommendationsTooltip(caseId) {
  const recs = getCaseGraphRecommendations(caseId);
  if (!recs.length) return '<span class="muted">—</span>';
  const safeId = escapeHtml(caseId).replace(/'/g, "\\'");
  return `<ul class="case-rec-tooltip-list">${recs.map(r =>
    `<li><button type="button" class="link-btn btn-sm" onclick="runCaseGraphRecommendation('${safeId}','${r.id}')">${escapeHtml(r.text)}</button></li>`
  ).join('')}</ul>`;
}

function getStaffWorkloadMetrics(p = getActivePersona()) {
  const rows = new Map();
  getPersonaScopedCases().forEach(c => {
    const name = c.lead || '—';
    if (!rows.has(name)) rows.set(name, { name, openCases: 0, urgent: 0, overdueSla: 0 });
    const row = rows.get(name);
    if (isOpenCase(c)) row.openCases += 1;
    if (c.daysLeft != null && c.daysLeft <= 7) row.urgent += 1;
  });
  platformRequests.filter(r => requestMatchesPersona(r, p) && isRequestSlaOverdue(r)).forEach(r => {
    const token = (r.from || '').split('·')[0]?.trim().split(' ').pop() || '';
    rows.forEach(row => {
      if (token && row.name.includes(token)) row.overdueSla += 1;
    });
  });
  return [...rows.values()].sort((a, b) => (b.urgent * 3 + b.overdueSla * 2 + b.openCases) - (a.urgent * 3 + a.overdueSla * 2 + a.openCases));
}

function renderStaffWorkloadPanel(p) {
  if (!hasLeadCapabilities(p)) return '';
  const metrics = getStaffWorkloadMetrics(p);
  if (!metrics.length) return '';
  return `<div class="panel staff-workload-panel">
    <div class="panel-header">
      <h2>Нагрузка следователей · ${escapeHtml(p.caseScope?.region || p.region)}</h2>
      <button type="button" class="btn-sm" onclick="exportStaffWorkloadCsv()">CSV</button>
    </div>
    <p class="muted staff-workload-hint">Открытые дела · срочные сроки (≤7 дн.) · просрочка SLA запросов · перегруз при &gt;5 срочных</p>
    <div class="table-scroll"><table class="data-table staff-workload-table"><thead><tr>
      <th>Следователь</th><th>Дела</th><th>Срочные</th><th>SLA</th><th>Статус</th>
    </tr></thead><tbody>
      ${metrics.map(m => {
        const overloaded = m.urgent > 5;
        return `<tr class="${overloaded ? 'staff-workload-row--overload row-danger' : m.urgent > 0 ? 'row-warning' : ''}">
          <td>${escapeHtml(m.name)}</td>
          <td>${m.openCases}</td>
          <td>${m.urgent ? `<strong class="staff-workload-urgent">${m.urgent}</strong>` : '0'}</td>
          <td>${m.overdueSla ? `<span class="sla-overdue-badge">${m.overdueSla}</span>` : '0'}</td>
          <td>${overloaded ? '<span class="staff-workload-badge">перегруз</span>' : '<span class="muted">норма</span>'}</td>
        </tr>`;
      }).join('')}
    </tbody></table></div>
  </div>`;
}

function renderClusterCaseCompare(caseIdA, caseIdB) {
  const ca = getCaseById(caseIdA);
  const cb = getCaseById(caseIdB);
  if (!ca || !cb) return '<p class="muted">Дело не найдено</p>';
  const fields = [
    ['Регион', ca.region, cb.region],
    ['Статья', ca.article, cb.article],
    ['Этап', ca.stage, cb.stage],
    ['Следователь', ca.lead, cb.lead],
    ['Срок УПК', ca.daysLeft != null ? `${ca.daysLeft} дн.` : '—', cb.daysLeft != null ? `${cb.daysLeft} дн.` : '—'],
    ['Фигуранты', String((ca.figurants || []).length), String((cb.figurants || []).length)],
    ['Узлов в графе', String(countGraphNodesForCase(caseIdA)), String(countGraphNodesForCase(caseIdB))]
  ];
  const tokens = CLUSTER_SHARED_TOKENS[ca.cluster] || [];
  const rows = fields.map(([label, va, vb]) => {
    const diff = va !== vb;
    return `<tr class="${diff ? 'cluster-compare-diff' : ''}">
      <th>${escapeHtml(label)}</th>
      <td>${escapeHtml(va)}</td>
      <td>${escapeHtml(vb)}</td>
    </tr>`;
  }).join('');
  return `<div class="cluster-compare-grid">
    <table class="data-table cluster-compare-table">
      <thead><tr><th>Поле</th><th>${escapeHtml(caseIdA)}</th><th>${escapeHtml(caseIdB)}</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
    ${tokens.length ? `<p class="muted cluster-compare-tokens">Общие токены кластера: ${tokens.map(t => `<span class="cluster-token-pill">${escapeHtml(t)}</span>`).join(' ')}</p>` : ''}
  </div>`;
}

function updateClusterCaseCompare() {
  activeClusterCompareA = document.getElementById('cluster-compare-a')?.value || null;
  activeClusterCompareB = document.getElementById('cluster-compare-b')?.value || null;
  const host = document.getElementById('cluster-compare-host');
  if (!host) return;
  if (activeClusterCompareA && activeClusterCompareB && activeClusterCompareA !== activeClusterCompareB) {
    host.innerHTML = renderClusterCaseCompare(activeClusterCompareA, activeClusterCompareB);
  } else {
    host.innerHTML = '<p class="muted">Выберите два разных дела кластера</p>';
  }
}

function retryFailedRequest(requestId) {
  const r = getRequestById(requestId);
  if (!r || !['rejected', 'expired'].includes(r.status)) return;
  const retryNum = (r.retryCount || 0) + 1;
  const note = `повтор №${retryNum}`;
  const agencyEntry = agencyRegistry.find(a => a.name === r.agency || a.name === r.target || r.target?.includes(a.name));
  const agencyId = agencyEntry?.id || (r.agency === 'ФНС' ? 'FNS' : r.agency === 'МВД (ГИАЦ)' ? 'MVD' : null);
  openNewRequestModal(r.scope, agencyId, null, {
    subject: r.subject ? `${r.subject} · ${note}` : note,
    legal: r.legal || '',
    typeLabel: r.type,
    skipTemplateReset: true
  });
  r.retryCount = retryNum;
  const title = document.getElementById('request-modal-title');
  if (title) title.textContent = `Повтор запроса · ${r.id} (${note})`;
  pushAuditEntry('Повтор отклонённого запроса', `${requestId} · ${note}`, 'ПОЛ-003');
  showToast(`${r.id}: черновик с пометкой «${note}»`);
}

function linkOsintFindingToCase(findingId, caseId) {
  const scanId = selectedOsintScanId;
  const findings = osintFindingsByScan[scanId];
  const f = findings?.find(x => x.id === findingId);
  const targetCase = caseId || activeCaseId;
  if (!f || !targetCase) return;
  if (f.importedToGraph) {
    showToast('Находка уже в графе.');
    return;
  }
  if (f.requiresReview && f.reviewStatus !== 'approved') {
    showToast('Сначала подтвердите находку (✓).');
    return;
  }
  const result = attachFindingToGraph(f, targetCase);
  if (result.action === 'skipped') {
    showToast('Тип находки не поддерживается для графа.');
    return;
  }
  f.importedToGraph = true;
  const anchor = getGraphCaseAnchor(result.caseId || targetCase);
  graphView?.afterDataChange?.(result.nodeId || anchor.anchorId);
  pushCaseProvenance(result.caseId || targetCase, {
    type: 'osint',
    source: 'OSINT → граф',
    detail: `${f.value} · ${osintTypeLabels[f.normalizedType] || f.normalizedType}`,
    policy: 'ПОЛ-006'
  });
  appendCaseTimelineEntry(result.caseId || targetCase, `OSINT: находка в графе · ${graphLabelForFinding(f)}`, { osint: true, highlight: true });
  pushAuditEntry('OSINT в граф и цепочку', `${findingId} · ${targetCase}`, 'ПОЛ-006');
  renderOsintFindings(scanId);
  if (activeCaseId === targetCase) renderCaseDetail(targetCase);
  showToast('Находка добавлена в граф и цепочку происхождения');
}

function loadNotificationsRead() {
  try { return JSON.parse(localStorage.getItem(NOTIFICATIONS_READ_STORAGE) || '[]'); }
  catch { return []; }
}

function saveNotificationsRead(ids) {
  try { localStorage.setItem(NOTIFICATIONS_READ_STORAGE, JSON.stringify(ids)); } catch { /* demo */ }
}

function markNotificationRead(notifId) {
  const read = loadNotificationsRead();
  if (!read.includes(notifId)) {
    read.push(notifId);
    saveNotificationsRead(read);
  }
  refreshNotificationCenter();
}

function loadNotifications(p = getActivePersona()) {
  const read = loadNotificationsRead();
  const items = [];

  if (canAccessView('cases', p)) {
    getPersonaScopedCases()
      .filter(c => c.daysLeft != null && c.daysLeft <= 3)
      .forEach(c => {
        items.push({
          id: `deadline-${c.id}`,
          kind: 'deadline',
          severity: c.daysLeft <= 2 ? 'critical' : 'warning',
          title: `Срок УПК · ${c.id}`,
          sub: `Осталось ${c.daysLeft} дн. · ${c.article.replace(' УК РФ', '')}`,
          view: 'case',
          target: c.id
        });
      });
  }

  if (canAccessView('requests', p)) {
    getOverdueRequestsForPersona(p).forEach(r => {
      items.push({
        id: `sla-${r.id}`,
        kind: 'sla',
        severity: 'critical',
        title: `Просрочен SLA · ${r.id}`,
        sub: `${r.type} · ${r.target || ''}`.trim(),
        view: 'requests'
      });
    });
  }

  if (hasLeadCapabilities(p)) {
    getPendingAccessRequestsForViewer(p).forEach(r => {
      items.push({
        id: `access-${r.id}`,
        kind: 'access',
        severity: 'warning',
        title: `Заявка на доступ · ${r.featureLabel}`,
        sub: r.id,
        view: 'staff',
        staffTab: 'hr'
      });
    });
  }

  const impact = loadLegislationImpact();
  if (impact?.cases?.length && (canAccessView('cases', p) || canAccessView('deadlines', p))) {
    items.push({
      id: 'legislation-impact',
      kind: 'legislation',
      severity: 'warning',
      title: 'Изменения законодательства (УПК)',
      sub: `Затронуто дел: ${impact.cases.length}`,
      view: 'regulations'
    });
  }

  if (canAccessView('horizon', p)) {
    const col = horizonProfilesByCase[activeHorizonCaseId]?.collision;
    if (col && getHorizonCollisionStatus(activeHorizonCaseId) !== 'coordinated') {
      items.push({
        id: 'horizon-collision',
        kind: 'horizon',
        severity: 'warning',
        title: 'Параллельное расследование',
        sub: `${col.agency} · ${col.caseToken}`,
        view: 'horizon'
      });
    }
  }

  return items.map(it => ({ ...it, read: read.includes(it.id) }));
}

function getNotifications(p = getActivePersona()) {
  return loadNotifications(p);
}

function navigateNotification(item) {
  markNotificationRead(item.id);
  closeNotificationsPanel();
  if (item.view === 'case' && item.target) openCase(item.target);
  else if (item.view === 'requests') showView('requests');
  else if (item.view === 'staff') { staffTab = item.staffTab || 'hr'; showView('staff'); }
  else if (item.view === 'horizon') showView('horizon');
  else if (item.view === 'regulations') showUtilView('regulations');
}

function renderNotificationsPanel() {
  const panel = document.getElementById('notifications-panel');
  if (!panel) return;
  const items = loadNotifications();
  const unread = items.filter(n => !n.read).length;
  if (!items.length) {
    panel.innerHTML = `<div class="notifications-panel-head"><h3>Уведомления</h3></div><p class="notifications-empty muted">Нет активных сигналов</p>`;
    return;
  }
  panel.innerHTML = `
    <div class="notifications-panel-head">
      <h3>Уведомления${unread ? ` · ${unread}` : ''}</h3>
      ${unread ? `<button type="button" class="btn-sm" onclick="markAllNotificationsRead()">Прочитать все</button>` : ''}
    </div>
    <ul class="notifications-list">${items.map(n => `
      <li><button type="button" class="notifications-item notifications-item--${n.severity} ${n.read ? '' : 'unread'}"
        onclick="handleNotificationClick('${escapeHtml(n.id)}')">
        <span class="notifications-item-title">${escapeHtml(n.title)}</span>
        <span class="notifications-item-sub">${escapeHtml(n.sub)}</span>
      </button></li>`).join('')}
    </ul>`;
}

function handleNotificationClick(notifId) {
  const item = loadNotifications().find(n => n.id === notifId);
  if (item) navigateNotification(item);
}

function markAllNotificationsRead() {
  const ids = loadNotifications().map(n => n.id);
  saveNotificationsRead([...new Set([...loadNotificationsRead(), ...ids])]);
  refreshNotificationCenter();
}

function refreshNotificationCenter() {
  const badge = document.getElementById('header-notifications-badge');
  const unread = loadNotifications().filter(n => !n.read).length;
  if (badge) {
    badge.textContent = String(unread);
    badge.classList.toggle('hidden', unread === 0);
  }
  const panel = document.getElementById('notifications-panel');
  if (panel && !panel.classList.contains('hidden')) renderNotificationsPanel();
}

function toggleNotificationsPanel() {
  const panel = document.getElementById('notifications-panel');
  const btn = document.getElementById('header-notifications-btn');
  if (!panel) return;
  const open = panel.classList.toggle('hidden') === false;
  if (btn) btn.setAttribute('aria-expanded', open ? 'true' : 'false');
  if (open) renderNotificationsPanel();
  else closeGlobalSearch();
}

function closeNotificationsPanel() {
  document.getElementById('notifications-panel')?.classList.add('hidden');
  document.getElementById('header-notifications-btn')?.setAttribute('aria-expanded', 'false');
}

function openGlobalSearch() {
  const dropdown = document.getElementById('global-search-dropdown');
  const input = document.getElementById('global-search-input');
  if (dropdown) dropdown.classList.remove('hidden');
  if (input) input.setAttribute('aria-expanded', 'true');
  closeNotificationsPanel();
  runGlobalSearch(input?.value || '');
}

function closeGlobalSearch() {
  document.getElementById('global-search-dropdown')?.classList.add('hidden');
  document.getElementById('global-search-input')?.setAttribute('aria-expanded', 'false');
}

const RECENT_CASES_STORAGE = 'epsok-recent-cases';
const RECENT_CASES_MAX = 8;

function loadRecentCaseIds() {
  try {
    const raw = JSON.parse(localStorage.getItem(RECENT_CASES_STORAGE) || '[]');
    return Array.isArray(raw) ? raw.filter(id => typeof id === 'string') : [];
  } catch {
    return [];
  }
}

function recordRecentCase(caseId) {
  if (!caseId) return;
  const ids = loadRecentCaseIds().filter(id => id !== caseId);
  ids.unshift(caseId);
  localStorage.setItem(RECENT_CASES_STORAGE, JSON.stringify(ids.slice(0, RECENT_CASES_MAX)));
}

function getRecentCasesForSearch(limit = 5) {
  return loadRecentCaseIds()
    .filter(id => personaCanBrowseCase(id) && getCaseById(id))
    .slice(0, limit)
    .map(id => getCaseById(id));
}

function renderGlobalSearchEmptyState() {
  const bookmarkIds = loadCaseBookmarks();
  const bookmarked = bookmarkIds
    .filter(id => personaCanBrowseCase(id) && getCaseById(id))
    .slice(0, 4)
    .map(id => getCaseById(id));
  const recent = getRecentCasesForSearch(5).filter(c => !bookmarkIds.includes(c.id));
  const bookmarkHtml = bookmarked.length
    ? `<div class="global-search-section">
        <p class="global-search-section-label">Избранные дела</p>
        ${bookmarked.map(c => `
          <button type="button" class="global-search-item" role="option" onclick="closeGlobalSearch();openCase('${c.id}')">
            <span class="global-search-item-kind">★</span>
            <span class="global-search-item-label">${escapeHtml(c.id)}</span>
            <span class="global-search-item-sub">${escapeHtml(c.article)} · ${escapeHtml(c.lead)}</span>
          </button>`).join('')}
      </div>`
    : '';
  const recentHtml = recent.length
    ? `<div class="global-search-section">
        <p class="global-search-section-label">Недавние дела</p>
        ${recent.map(c => `
          <button type="button" class="global-search-item" role="option" onclick="closeGlobalSearch();openCase('${c.id}')">
            <span class="global-search-item-kind">Недавнее</span>
            <span class="global-search-item-label">${escapeHtml(c.id)}</span>
            <span class="global-search-item-sub">${escapeHtml(c.article)} · ${escapeHtml(c.lead)}</span>
          </button>`).join('')}
      </div>`
    : '';

  const p = getActivePersona();
  const quickNav = [
    { label: 'Дашборд', action: "showView('dashboard')", view: 'dashboard' },
    { label: 'Реестр дел', action: "showView('cases')", view: 'cases' },
    { label: 'Запросы', action: "showView('requests')", view: 'requests' },
    { label: 'Справка', action: "showUtilView('help')" }
  ].filter(item => !item.view || canAccessView(item.view, p));

  const quickHtml = quickNav.length
    ? `<div class="global-search-section">
        <p class="global-search-section-label">Быстрый переход</p>
        ${quickNav.map(item => `
          <button type="button" class="global-search-item global-search-item--compact" role="option" onclick="closeGlobalSearch();${item.action}">
            <span class="global-search-item-label">${escapeHtml(item.label)}</span>
          </button>`).join('')}
      </div>`
    : '';

  return `${bookmarkHtml}${recentHtml}${quickHtml}
    <p class="global-search-hint muted">Поиск: номер дела, статья, ФИО, ID запроса · <kbd>Ctrl+K</kbd> · ↑↓ Enter · <button type="button" class="link-inline" onclick="closeGlobalSearch();openShortcutsModal()">горячие клавиши</button></p>`;
}

let globalSearchActiveIndex = -1;

function resetGlobalSearchSelection() {
  globalSearchActiveIndex = -1;
  document.querySelectorAll('.global-search-item.is-active').forEach(el => el.classList.remove('is-active'));
}

function highlightGlobalSearchItem(idx) {
  const items = [...document.querySelectorAll('#global-search-dropdown .global-search-item')];
  if (!items.length) return;
  globalSearchActiveIndex = ((idx % items.length) + items.length) % items.length;
  items.forEach((el, i) => el.classList.toggle('is-active', i === globalSearchActiveIndex));
  items[globalSearchActiveIndex]?.scrollIntoView({ block: 'nearest' });
}

function activateGlobalSearchSelection() {
  const items = document.querySelectorAll('#global-search-dropdown .global-search-item');
  if (globalSearchActiveIndex >= 0 && items[globalSearchActiveIndex]) {
    items[globalSearchActiveIndex].click();
    return true;
  }
  return false;
}

function openShortcutsModal() {
  document.getElementById('shortcuts-modal')?.classList.remove('hidden');
}

function closeShortcutsModal() {
  document.getElementById('shortcuts-modal')?.classList.add('hidden');
}

function runGlobalSearch(query) {
  const dropdown = document.getElementById('global-search-dropdown');
  if (!dropdown) return;
  const q = (query || '').trim().toLowerCase();
  if (!q) {
    dropdown.innerHTML = renderGlobalSearchEmptyState();
    dropdown.classList.remove('hidden');
    resetGlobalSearchSelection();
    return;
  }
  const p = getActivePersona();
  const results = [];

  if (canAccessView('cases', p)) {
    getPersonaScopedCases().forEach(c => {
      const hay = [c.id, c.article, c.lead, c.crimeType, c.cluster].filter(Boolean).join(' ').toLowerCase();
      if (hay.includes(q)) {
        results.push({ kind: 'Дело', id: c.id, label: c.id, sub: `${c.article} · ${c.lead}`, action: `openCase('${c.id}')` });
      }
    });
  }

  if (canAccessView('requests', p)) {
    platformRequests.filter(r => requestMatchesPersona(r, p)).forEach(r => {
      const hay = [r.id, r.subject, r.type, r.target].filter(Boolean).join(' ').toLowerCase();
      if (hay.includes(q)) {
        results.push({ kind: 'Запрос', id: r.id, label: r.id, sub: r.subject || r.type, action: `openRequestFromSearch('${r.id}')` });
      }
    });
  }

  if (canAccessView('suspects', p)) {
    filterSuspectDossiers(suspectDossiers.slice()).forEach(s => {
      const name = [s.lastName, s.firstName, s.patronymic].filter(Boolean).join(' ');
      const hay = [name, s.id, s.caseId].join(' ').toLowerCase();
      if (hay.includes(q)) {
        results.push({ kind: 'Фигурант', id: s.id, label: name, sub: s.caseId, action: `selectSuspectFromSearch('${s.id}')` });
      }
    });
  }

  if (canAccessView('agencies', p)) {
    getVisibleAgencies(p).forEach(a => {
      const hay = [a.name, a.summary, a.law, agencyCategoryLabels[a.category], ...(a.functions || [])].join(' ').toLowerCase();
      if (hay.includes(q)) {
        results.push({ kind: 'Ведомство', id: a.id, label: a.name, sub: agencyCategoryLabels[a.category] || '', action: `selectAgencyFromSearch('${a.id}')` });
      }
    });
  }

  if (!results.length) {
    dropdown.innerHTML = '<p class="global-search-hint muted">Ничего не найдено в вашем контуре</p>';
  } else {
    dropdown.innerHTML = results.slice(0, 12).map(r => `
      <button type="button" class="global-search-item" role="option" onclick="closeGlobalSearch();${r.action}">
        <span class="global-search-item-kind">${escapeHtml(r.kind)}</span>
        <span class="global-search-item-label">${escapeHtml(r.label)}</span>
        <span class="global-search-item-sub">${escapeHtml(r.sub)}</span>
      </button>`).join('');
  }
  dropdown.classList.remove('hidden');
  resetGlobalSearchSelection();
}

function selectAgencyFromSearch(agencyId) {
  activeAgencyId = agencyId;
  showView('agencies');
}

function handleNavSequenceKey(key, p = getActivePersona()) {
  const routes = {
    c: () => canAccessView('cases', p) && showView('cases'),
    r: () => canAccessView('requests', p) && showView('requests'),
    d: () => canAccessView('deadlines', p) && showView('deadlines'),
    a: () => canAccessView('agencies', p) && showView('agencies'),
    m: () => canAccessView('mail', p) && showView('mail')
  };
  if (pendingNavSequence === 'g' && routes[key]) {
    routes[key]();
    pendingNavSequence = null;
    clearTimeout(pendingNavTimer);
    return true;
  }
  if (key === 'g') {
    pendingNavSequence = 'g';
    clearTimeout(pendingNavTimer);
    pendingNavTimer = setTimeout(() => { pendingNavSequence = null; }, 900);
    return true;
  }
  pendingNavSequence = null;
  return false;
}

function selectSuspectFromSearch(id) {
  activeSuspectId = id;
  showView('suspects');
  renderSuspects();
}

function openRequestFromSearch(requestId) {
  if (!getRequestById(requestId)) {
    showToast('Запрос не найден в вашем контуре.');
    return;
  }
  activeRequestHighlightId = requestId;
  showView('requests');
  requestAnimationFrame(() => {
    const row = document.querySelector(`#requests-table-body tr[data-request-id="${requestId}"]`);
    row?.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
  });
  setTimeout(() => { activeRequestHighlightId = null; renderRequests(); }, 4000);
}

function initHeaderChrome() {
  if (window.__epsokHeaderChromeBound) return;
  window.__epsokHeaderChromeBound = true;

  const searchInput = document.getElementById('global-search-input');
  searchInput?.addEventListener('keydown', (e) => {
    const dropdown = document.getElementById('global-search-dropdown');
    if (!dropdown || dropdown.classList.contains('hidden')) return;
    const items = dropdown.querySelectorAll('.global-search-item');
    if (!items.length) return;
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      highlightGlobalSearchItem(globalSearchActiveIndex + 1);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      highlightGlobalSearchItem(globalSearchActiveIndex < 0 ? items.length - 1 : globalSearchActiveIndex - 1);
    } else if (e.key === 'Enter' && globalSearchActiveIndex >= 0) {
      e.preventDefault();
      activateGlobalSearchSelection();
    }
  });

  function syncNetworkStatusPill() {
    const pill = document.getElementById('network-status-pill');
    if (!pill || !isAppLoggedIn()) {
      pill?.classList.add('hidden');
      return;
    }
    pill.classList.remove('hidden');
    const online = navigator.onLine;
    pill.textContent = online ? '● В сети' : '○ Офлайн';
    pill.classList.toggle('online', online);
    pill.classList.toggle('offline', !online);
    pill.title = online
      ? 'Соединение с контуром ЕПСОК активно'
      : 'Нет сети · изменения сохраняются локально';
  }

  window.addEventListener('online', () => { syncNetworkStatusPill(); updateHeaderStatusSummary(); });
  window.addEventListener('offline', () => { syncNetworkStatusPill(); updateHeaderStatusSummary(); });
  syncNetworkStatusPill();
  applyHeaderStatusCompact();

  document.addEventListener('keydown', (e) => {
    const tag = (e.target?.tagName || '').toLowerCase();
    const typing = tag === 'input' || tag === 'textarea' || tag === 'select' || e.target?.isContentEditable;
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
      e.preventDefault();
      document.getElementById('global-search-input')?.focus();
      openGlobalSearch();
      return;
    }
    if (!typing && e.key === '/' && !e.ctrlKey && !e.metaKey && !e.altKey) {
      e.preventDefault();
      document.getElementById('global-search-input')?.focus();
      openGlobalSearch();
      return;
    }
    if (e.key === 'Escape') {
      closeGlobalSearch();
      closeNotificationsPanel();
      closeShortcutsModal();
      return;
    }
    if (!typing && e.key === '?' && !e.ctrlKey && !e.metaKey && !e.altKey && isAppLoggedIn()) {
      e.preventDefault();
      openShortcutsModal();
      return;
    }
    if (!typing && !e.ctrlKey && !e.metaKey && !e.altKey && isAppLoggedIn()) {
      const k = e.key.toLowerCase();
      if (handleNavSequenceKey(k, getActivePersona())) {
        e.preventDefault();
      }
    }
  });

  document.addEventListener('click', (e) => {
    if (!e.target.closest('#header-search-wrap')) closeGlobalSearch();
    if (!e.target.closest('#header-notifications-wrap')) closeNotificationsPanel();
  });
}

function refreshHeaderChrome() {
  refreshNotificationCenter();
  const pill = document.getElementById('network-status-pill');
  if (pill && isAppLoggedIn()) {
    const online = navigator.onLine;
    pill.classList.remove('hidden');
    pill.textContent = online ? '● В сети' : '○ Офлайн';
    pill.classList.toggle('online', online);
    pill.classList.toggle('offline', !online);
  } else if (pill) {
    pill.classList.add('hidden');
  }
  updateHeaderStatusSummary();
}

function getManagerRoiMetrics(p) {
  const scoped = platformRequests.filter(r => {
    if (p.department && r.department === p.department) return true;
    if (p.region && r.from?.includes(p.region.split(' ')[0])) return true;
    return requestMatchesPersona(r, p);
  });
  const fulfilled = scoped.filter(r => r.status === 'fulfilled');
  const pending = scoped.filter(r => ['progress', 'submitted'].includes(r.status)).length;
  const avgHours = fulfilled.length
    ? (fulfilled.reduce((sum, r) => sum + (r.scope === 'interagency' ? 28 : 6), 0) / fulfilled.length)
    : 18;
  const avgLabel = avgHours >= 24
    ? `${(avgHours / 24).toFixed(1).replace('.', ',')} дн.`
    : `${Math.round(avgHours)} ч`;
  return { fulfilledCount: fulfilled.length, pendingCount: pending, avgResponse: avgLabel };
}

function getRequestAnalyticsLast30(p) {
  const scoped = platformRequests.filter(r => requestMatchesPersona(r, p));
  const fulfilled = scoped.filter(r => r.status === 'fulfilled').length;
  const pending = scoped.filter(r => ['progress', 'submitted', 'draft'].includes(r.status)).length;
  const overdue = scoped.filter(r => isRequestSlaOverdue(r)).length;
  const max = Math.max(fulfilled, pending, overdue, 1);
  return { fulfilled, pending, overdue, max };
}

function renderRequestAnalyticsChart(p) {
  const { fulfilled, pending, overdue, max } = getRequestAnalyticsLast30(p);
  const bar = (n, cls, label) => {
    const h = Math.round((n / max) * 100);
    return `<div class="req-analytics-bar-wrap" title="${label}: ${n}">
      <div class="req-analytics-bar ${cls}" style="height:${h}%"></div>
      <span class="req-analytics-val">${n}</span>
      <span class="req-analytics-lbl">${label}</span>
    </div>`;
  };
  return `<div class="panel req-analytics-panel">
    <h2>Запросы · 30 дней</h2>
    <div class="req-analytics-chart">${bar(fulfilled, 'fulfilled', 'исполнено')}${bar(pending, 'pending', 'в работе')}${bar(overdue, 'overdue', 'просрочено')}</div>
    <p class="muted req-analytics-hint">Демо-данные platformRequests · SLA по уровню запроса</p>
    </div>`;
}

function getProsecutorHealthRows(p = getActivePersona()) {
  return getPersonaScopedCases()
    .map(c => ({ c, m: getCaseHealthMetrics(c.id) }))
    .filter(x => x.m && (x.m.deadlineRisk !== 'ok' || x.m.graphGap || x.m.requestBacklog > 0))
    .sort((a, b) => {
      const order = { critical: 0, warning: 1, watch: 2, ok: 3 };
      return (order[a.m.deadlineRisk] - order[b.m.deadlineRisk])
        || (b.m.requestBacklog - a.m.requestBacklog);
    });
}

function renderProsecutorDashboard(p) {
  const el = document.getElementById('dash-prosecutor');
  if (!el) return;
  const scopedCases = getPersonaScopedCases();
  const cases = scopedCases.filter(c => c.daysLeft != null && c.daysLeft <= 7);
  const healthRows = getProsecutorHealthRows(p).slice(0, 8);
  const impact = loadLegislationImpact();
  const impactBanner = impact?.cases?.length
    ? `<div class="legislation-impact-banner prosecutor-impact-banner" id="prosecutor-legislation-impact" role="status">${renderLegislationImpactBannerHtml(impact, { compact: true })}</div>`
    : '';
  const cards = [];
  if (canAccessView('deadlines', p)) {
    cards.push(renderKpiCard({ value: cases.length, label: 'Дела с риском срока', trend: 'контроль УПК', trendType: 'warn', variant: 'deadlines', icon: '⏱', onclick: "showView('deadlines')" }));
  }
  if (canAccessView('cases', p)) {
    cards.push(renderKpiCard({ value: scopedCases.length, label: 'Дел в надзоре', trend: escapeHtml(p.region), variant: 'cases', icon: '◫', onclick: "showView('cases')" }));
  }
  if (canAccessView('horizon', p)) {
    cards.push(renderKpiCard({ value: 3, label: 'Сигналы «Горизонт»', trend: 'надзор', trendType: 'up', variant: 'horizon', icon: '◈', onclick: "showView('horizon')" }));
  }
  const healthPanel = healthRows.length ? `<div class="panel case-health-panel">
      <div class="panel-header">
        <h2>Состояние дел · надзорный контур</h2>
        <button type="button" class="btn-sm" onclick="exportProsecutorHealthCsv()">CSV</button>
      </div>
      <p class="muted case-health-hint">Сроки УПК · пробелы графа · неисполненные запросы по делам в зоне ответственности</p>
      <div class="table-scroll"><table class="data-table case-health-table"><thead><tr>
        <th>Дело</th><th>Срок УПК</th><th>Граф</th><th>Запросы</th><th>Риск</th><th>Рекомендации</th>
      </tr></thead><tbody>
        ${healthRows.map(({ c, m }) => `<tr class="${m.deadlineRisk === 'critical' ? 'row-danger' : m.deadlineRisk === 'warning' ? 'row-warning' : ''}">
          <td><button type="button" class="case-link" onclick="openCase('${c.id}')">${c.id}</button></td>
          <td>${m.daysLeft != null ? `${m.daysLeft} дн.` : '—'}</td>
          <td>${m.graphGap ? `<span class="case-health-gap" title="${escapeHtml(getCaseGraphRecommendations(c.id).map(r => r.text).join(' · ') || 'пробел')}">пробел (${m.graphNodes} узл.)</span>` : `${m.graphNodes} узл.`}</td>
          <td>${m.requestBacklog ? `<strong>${m.requestBacklog}</strong> в работе` : '<span class="muted">нет</span>'}</td>
          <td>${renderCaseHealthRiskBadge(m.deadlineRisk)}</td>
          <td>${renderGraphRecommendationsTooltip(c.id)}</td>
        </tr>`).join('')}
      </tbody></table></div>
    </div>` : '';
  el.innerHTML = `
    ${impactBanner}
    ${cards.length ? `<div class="kpi-grid" style="margin-bottom:1.25rem">${cards.join('')}</div>` : ''}
    ${healthPanel}
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
  const clusterStats = getClusterEntityCount('МВ-2847');
  const cards = [];
  if (canAccessView('horizon', p)) {
    cards.push(renderKpiCard({ value: 3, label: 'Сигналы «Горизонт»', trend: 'МВ-2847', trendType: 'up', variant: 'horizon', icon: '◈', onclick: "showView('horizon')" }));
  }
  if (canAccessView('graph', p)) {
    cards.push(renderKpiCard({ value: clusterStats.cases, label: 'Дел в кластере МВ-2847', trend: `${clusterStats.regions} регионов`, variant: 'cases', icon: '◫', onclick: "openClusterHub('МВ-2847')" }));
    cards.push(renderKpiCard({ value: clusterStats.entities, label: 'Обезлич. сущностей', trend: 'общие токены', trendType: 'up', variant: 'links', icon: '◎', onclick: "openClusterHub('МВ-2847')" }));
  }
  const timeline = CLUSTER_TIMELINE_EVENTS['МВ-2847'] || [];
  el.innerHTML = `
    ${cards.length ? `<div class="kpi-grid" style="margin-bottom:1.25rem">${cards.join('')}</div>` : ''}
    <div class="grid-2">
      <div class="panel analyst-cluster-panel">
        <div class="panel-header"><h2>Кластер МВ-2847 · лента</h2>
          <button type="button" class="btn-sm" onclick="openClusterHub('МВ-2847')">Хаб кластера</button>
        </div>
        <ul class="cluster-timeline">${timeline.map(e =>
          `<li><span class="cluster-timeline-date">${escapeHtml(e.at)} · ${escapeHtml(e.region)}</span>${escapeHtml(e.text)}</li>`
        ).join('')}</ul>
        <p class="muted">Обезличенные события · без раскрытия персональных данных</p>
      </div>
      ${canAccessView('graph', p) ? `<div class="panel"><h2>Федеральные кластеры</h2>
        <div class="cluster-list">
          <div class="cluster-item"><span class="cluster-tag fraud">Мошенничество</span><span>МВ-2847 · ${clusterStats.regions} регионов</span>
            <button class="btn-sm" onclick="openClusterHub('МВ-2847')">Хаб</button>
            <button class="btn-sm" onclick="showView('graph')">Граф</button></div>
          ${canAccessView('horizon', p) ? `<div class="cluster-item"><span class="cluster-tag drugs">Наркотики</span><span>МВ-1923 · 3 региона</span>
            <button class="btn-sm" onclick="showView('horizon')">Горизонт</button></div>` : ''}
        </div>
      </div>` : ''}
      <div class="panel"><h2>Доступные модули</h2>
        <ul class="info-list" style="margin-left:1rem">
          ${canAccessView('graph', p) ? '<li>Граф связей — обезличенные узлы</li>' : ''}
          ${canAccessView('horizon', p) ? '<li>«Горизонт» — федеральные совпадения</li>' : ''}
          ${canAccessView('cases', p) ? '<li>Реестр дел — без персональных данных</li>' : ''}
        </ul>
      </div>
    </div>`;
}

function renderCourtDashboard(p) {
  const el = document.getElementById('dash-court');
  if (!el) return;
  const scopedCases = getPersonaScopedCases().filter(c => c.status === 'court' || (c.daysLeft != null && c.daysLeft <= 14));
  const urgent = scopedCases.filter(c => c.daysLeft != null && c.daysLeft <= 7);
  const cards = [];
  if (canAccessView('deadlines', p)) {
    cards.push(renderKpiCard({ value: urgent.length, label: 'Сроки до заседания', trend: 'контроль УПК', trendType: 'warn', variant: 'deadlines', icon: '⏱', onclick: "showView('deadlines')" }));
  }
  if (canAccessView('cases', p)) {
    cards.push(renderKpiCard({ value: scopedCases.length, label: 'Дел в судебном контуре', trend: escapeHtml(p.region), variant: 'cases', icon: '◫', onclick: "showView('cases')" }));
  }
  el.innerHTML = `
    ${cards.length ? `<div class="kpi-grid" style="margin-bottom:1.25rem">${cards.join('')}</div>` : ''}
    <div class="panel">
      <div class="panel-header">
        <h2>Судебный контур · ${escapeHtml(p.region)}</h2>
        <button type="button" class="btn-sm" onclick="exportCourtDashboardCsv()">CSV</button>
      </div>
      <p class="muted">Просмотр материалов и сроков · без следственных действий · ПОЛ-001</p>
      <div class="table-scroll"><table class="data-table"><thead><tr><th>Дело</th><th>Статья</th><th>Статус</th><th>Срок</th><th>Риск</th></tr></thead><tbody>
        ${scopedCases.slice(0, 10).map(c => `<tr class="${c.daysLeft != null && c.daysLeft <= 3 ? 'row-danger' : c.daysLeft != null && c.daysLeft <= 7 ? 'row-warning' : ''}">
          <td><button type="button" class="case-link" onclick="openCase('${c.id}')">${c.id}</button></td>
          <td>${escapeHtml(c.article.replace(' УК РФ', ''))}</td>
          <td><span class="badge ${c.status}">${caseStatusLabels[c.status]}</span></td>
          <td>${c.daysLeft != null ? `${c.daysLeft} дн.` : '—'}</td>
          <td>${renderCaseRiskBadge(c.id)}</td>
        </tr>`).join('') || '<tr><td colspan="5" class="muted">Нет дел в судебной очереди</td></tr>'}
      </tbody></table></div>
      <button type="button" class="btn-sm" style="margin-top:1rem" onclick="showView('deadlines')">Все сроки УПК</button>
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
    if (shouldOfferAccessRequest(viewId, p)) {
      openAccessRequestModal(viewId);
      return;
    }
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
    renderCasesRegistry();
  }
  if (viewId === 'case') renderCaseDetail(activeCaseId);
  if (viewId === 'deadlines') renderDeadlines();
  if (viewId === 'osint') { renderOsintPage(); renderOsintScans(); ensureOsintScanSelected(); renderEvidencePackages(); }
  if (viewId === 'horizon') renderHorizon();
  if (viewId === 'admin') renderAdmin();
  if (viewId === 'agencies') renderAgencies();
  if (viewId === 'requests') {
    renderRequests();
  }
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
  if (viewId === 'help') {
    initHelpNavSpy();
    requestAnimationFrame(updateHelpNavFromScroll);
  }
  syncCapabilityButtons(p);
  syncAccessRequestLink(p);
  updateHeaderContext();
  refreshHeaderChrome();
  if (!options?.skipSave) saveActiveView(viewId);
  if (!options?.skipHash) {
    syncAppDeepLinkHash({
      view: viewId,
      caseId: ['case', 'deadlines'].includes(viewId) ? (viewId === 'deadlines' ? activeDeadlinesCaseId : activeCaseId) : null,
      requestId: viewId === 'requests' ? activeRequestHighlightId : null,
      suspectId: viewId === 'suspects' ? activeSuspectId : null
    });
  }
}

function showToast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 3500);
}

const RUNTIME_AUDIT_STORAGE = 'epsok-runtime-audit';

function sanitizeDownloadFilename(filename) {
  return String(filename)
    .replace(/ЕПСОК/g, 'EPSOK')
    .replace(/епсок/gi, 'EPSOK')
    .replace(/[^\x20-\x7E]/g, '')
    .replace(/[<>:"/\\|?*]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '') || 'epsok-export.txt';
}

function downloadTextFile(filename, content, mime = 'text/plain;charset=utf-8') {
  const safeName = sanitizeDownloadFilename(filename);
  const blob = new Blob(['\uFEFF' + content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = safeName;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

async function sha256Hex(text) {
  const data = new TextEncoder().encode(text);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function formatAuditTimestamp() {
  const d = new Date();
  const pad = n => String(n).padStart(2, '0');
  return `${pad(d.getDate())}.${pad(d.getMonth() + 1)} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function loadRuntimeAuditLog() {
  try { return JSON.parse(localStorage.getItem(RUNTIME_AUDIT_STORAGE) || '[]'); }
  catch { return []; }
}

function pushAuditEntry(action, object, policy = 'ПОЛ-004') {
  const p = getActivePersona();
  const row = {
    time: formatAuditTimestamp(),
    user: p?.name || currentUser?.username || 'система',
    action,
    object,
    policy
  };
  const log = loadRuntimeAuditLog();
  log.unshift(row);
  if (log.length > 500) log.length = 500;
  localStorage.setItem(RUNTIME_AUDIT_STORAGE, JSON.stringify(log));
  return row;
}

function downloadMyAuditLog() {
  exportPersonalAuditCsv();
}

function exportPersonalAuditCsv() {
  const p = getActivePersona();
  const name = p?.name;
  const rows = loadRuntimeAuditLog().filter(r =>
    r.user === name || r.user === currentUser?.username
  );
  if (!rows.length) {
    showToast('В личном журнале пока нет записей.');
    return;
  }
  const header = 'Время;Пользователь;Действие;Объект;Политика';
  const body = rows.map(r => [r.time, r.user, r.action, r.object, r.policy].map(csvEscapeCell).join(';')).join('\n');
  downloadTextFile(`epsok-my-actions-${Date.now()}.csv`, `${header}\n${body}`, 'text/csv;charset=utf-8');
  pushAuditEntry('Экспорт личного журнала', `${rows.length} записей`, 'ПОЛ-005');
  showToast(`Мои действия: ${rows.length} записей (CSV)`);
}

function buildRequestResultDocument(r) {
  return `ЕПСОК · РЕЗУЛЬТАТ ЗАПРОСА
========================================
ID запроса:     ${r.id}
Тип:            ${r.type}
Кого/что:       ${r.subject || '—'}
Исполнитель:    ${r.target}
Инициатор:      ${r.from}
Канал:          ${REQUEST_SCOPES[r.scope]?.channel || 'СМЭВ'}
Правовое осн.:  ${r.legal || '—'}
Отправлен:      ${r.sent}
Исполнен:       ${r.fulfilledAt || '—'}

РЕЗУЛЬТАТ
---------
${r.result || '—'}

---
Документ сформирован в ЕПСОК · ${formatAuditTimestamp()}
Не является официальной выпиской без ЭП подписи исполнителя.
`;
}

function downloadRequestResult(requestId) {
  const r = getRequestById(requestId);
  if (!r?.result) {
    showToast('Нет результата для выгрузки.');
    return;
  }
  downloadTextFile(`${r.id}-result.txt`, buildRequestResultDocument(r));
  pushAuditEntry('Выгрузка результата запроса', r.id, 'ПОЛ-003');
  showToast(`${r.id}: файл результата сохранён`);
}

function buildCaseSummaryDocument(c) {
  const team = (c.team || []).map(m => `  · ${m.name} — ${m.role}`).join('\n') || '  —';
  const relatedReqs = platformRequests.filter(req =>
    req.subject?.includes(c.id) || req.from?.includes(c.lead?.split(' ')[0] || '')
  ).length;
  return `ЕПСОК · СПРАВКА ПО ДЕЛУ
========================
Номер:          ${c.id}
Статья:         ${c.article}
Состав:         ${c.crimeType}
Статус:         ${caseStatusLabels[c.status]}
Этап:           ${c.stage}
Ведомство:      ${c.agencyName}
Регион:         ${c.region}
Отдел:          ${c.department}
Ответственный:  ${c.lead}
Возбуждено:     ${c.opened}
Срок (дней):    ${c.daysLeft != null ? c.daysLeft : '—'}
Кластер:        ${c.cluster || '—'}

РАБОЧАЯ ГРУППА
${team}

АКТИВНОСТЬ
Связанных запросов: ${relatedReqs}
Узлов в графе:      ${countGraphNodesForCase(c.id)}

ХРОНОЛОГИЯ
${(c.timeline || []).map(t => `  ${t.date} — ${t.text}`).join('\n') || '  —'}

---
Сформировано: ${formatAuditTimestamp()} · ЕПСОК
Экспорт по ПОЛ-004 · только для служебного пользования
`;
}

function downloadCaseSummary(caseId) {
  const c = getCaseById(caseId);
  if (!c) return;
  const access = getCaseAccessMode(caseId);
  if (access.mode === 'denied') {
    showToast('ПОЛ-001: нет доступа к выгрузке.');
    return;
  }
  downloadTextFile(`${c.id}-spravka.txt`, appendDemoExportSignatureBlock(buildCaseSummaryDocument(c)));
  pushAuditEntry('Экспорт справки по делу', c.id, 'ПОЛ-004');
  pushCaseProvenance(caseId, { type: 'export', source: 'Экспорт', detail: 'Справка по делу (TXT)', policy: 'ПОЛ-004' });
  addEvidenceCustodyExportEntries(caseId, 'Экспорт справки (TXT)');
  if (document.getElementById('case-detail-root')?.querySelector('.evidence-custody-panel')) renderCaseDetail(caseId);
  refreshHeaderChrome();
  showToast(`Справка сохранена: ${sanitizeDownloadFilename(`${c.id}-spravka.txt`)}`);
}

function printCaseSummary(caseId) {
  const c = getCaseById(caseId);
  if (!c) return;
  const access = getCaseAccessMode(caseId);
  if (access.mode === 'denied') {
    showToast('ПОЛ-001: нет доступа к печати.');
    return;
  }
  const text = buildCaseSummaryDocument(c);
  const w = window.open('', '_blank', 'noopener,noreferrer');
  if (!w) {
    showToast('Разрешите всплывающие окна для печати.');
    return;
  }
  w.document.write(`<!DOCTYPE html><html lang="ru"><head><meta charset="UTF-8"><title>${escapeHtml(c.id)}</title>
<style>body{font-family:'Segoe UI',system-ui,sans-serif;max-width:720px;margin:1.5rem auto;line-height:1.5;font-size:12pt;color:#111}
pre{white-space:pre-wrap;font-family:inherit;margin:0}@media print{body{margin:0.8cm}}</style></head>
<body><pre>${escapeHtml(text)}</pre></body></html>`);
  w.document.close();
  w.focus();
  setTimeout(() => {
    try { w.print(); } catch { /* noop */ }
  }, 300);
  pushAuditEntry('Печать справки по делу', c.id, 'ПОЛ-004');
  showToast('Диалог печати открыт');
}

function buildCaseCourtPackageDocument(c) {
  const prov = getCaseProvenance(c.id);
  const reqs = getCaseRelatedRequests(c.id);
  const ex = explainCaseAccess(c.id);
  return `ЕПСОК · ПАКЕТ МАТЕРИАЛОВ ДЛЯ НАДЗОРА / СУДА
=============================================
Дело:           ${c.id}
Статья:         ${c.article} · ${c.crimeType}
Ведомство:      ${c.agencyName} · ${c.region}
Ответственный:  ${c.lead}
Статус доступа: ${ex.title} (${ex.policy})

РАБОЧАЯ ГРУППА
${(c.team || []).map(m => `  · ${m.name} — ${m.role}`).join('\n') || '  —'}

МЕЖВЕДОМСТВЕННЫЕ ЗАПРОСЫ (${reqs.length})
${reqs.map(r => `  · ${r.id} · ${r.type} · ${r.target} · ${r.status}${r.fulfilledAt ? ' · ' + r.fulfilledAt : ''}`).join('\n') || '  —'}

ЦЕПОЧКА ПРОИСХОЖДЕНИЯ (последние ${Math.min(prov.length, 15)} записей)
${prov.slice(0, 15).map((p, i) => `  ${i + 1}. [${p.at}] ${p.source}: ${p.detail} (${p.policy})`).join('\n')}

ХРОНОЛОГИЯ
${(c.timeline || []).map(t => `  ${t.date} — ${t.text}`).join('\n') || '  —'}

ГРАФ: ${countGraphNodesForCase(c.id)} узлов

---
Сформировано: ${formatAuditTimestamp()} · ЕПСОК
ПОЛ-004 · только для служебного пользования · не заменяет процессуальные документы
`;
}

function buildProsecutorSupervisionActDocument(c) {
  const m = getCaseHealthMetrics(c.id);
  const recs = getCaseGraphRecommendations(c.id);
  const violations = [];
  if (m?.deadlineRisk === 'critical') violations.push('Критический срок УПК · требуется контроль продления');
  if (m?.graphGap) violations.push('Пробел в графе связей · неполнота объектов расследования');
  if (m?.requestBacklog > 2) violations.push(`Неисполненные запросы: ${m.requestBacklog} в работе`);
  return `ЕПСОК · ПРОЕКТ АКТА ПРОКУРОРСКОГО НАДЗОРА
=============================================
Дело:              ${c.id}
Статья:            ${c.article} · ${c.crimeType}
Ведомство:         ${c.agencyName} · ${c.region}
Ответственный:     ${c.lead}
Срок УПК (ост.):   ${m?.daysLeft != null ? m.daysLeft + ' дн.' : '—'}

ПОКАЗАТЕЛИ СОСТОЯНИЯ ДЕЛА
Риск срока:        ${CASE_HEALTH_LABELS[m?.deadlineRisk] || '—'}
Узлов в графе:     ${m?.graphNodes ?? '—'}${m?.graphGap ? ' · ПРОБЕЛ' : ''}
Запросы в работе:  ${m?.requestBacklog ?? 0}

РЕКОМЕНДАЦИИ СИСТЕМЫ
${recs.length ? recs.map((r, i) => `  ${i + 1}. ${r.text}`).join('\n') : '  — нарушений не выявлено —'}

ЗАМЕЧАНИЯ / НАРУШЕНИЯ (проект)
${violations.length ? violations.map((v, i) => `  ${i + 1}. ${v}`).join('\n') : '  Существенных нарушений в демо-контуре не зафиксировано'}

---
Черновик для прокурорского надзора · ${formatAuditTimestamp()}
ПОЛ-002 · не является процессуальным документом
`;
}

function downloadProsecutorSupervisionAct(caseId) {
  const c = getCaseById(caseId);
  const p = getActivePersona();
  if (!c || (!['prosecutor', 'prosecutor_mil'].includes(p.roleType) && !isBetaRootPersona(p))) {
    showToast('Акт надзора доступен только прокурору (ПОЛ-002).');
    return;
  }
  downloadTextFile(`EPSOK-${caseId.replace(/ЕПСОК-/g, '')}-nadzor-act.txt`, appendDemoExportSignatureBlock(buildProsecutorSupervisionActDocument(c)));
  pushAuditEntry('Проект акта надзора', caseId, 'ПОЛ-002');
  showToast('Проект акта прокурорского надзора сохранён');
}

async function downloadCaseCourtPackage(caseId) {
  const c = getCaseById(caseId);
  if (!c) return;
  const access = getCaseAccessMode(caseId);
  if (access.mode === 'denied') {
    showToast('ПОЛ-001: нет доступа к пакету.');
    return;
  }
  const body = buildCaseCourtPackageDocument(c);
  let content = body;
  try {
    const hash = await sha256Hex(body);
    content = `${body}\nКОНТРОЛЬНАЯ СУММА\nSHA-256: ${hash}\n`;
  } catch (_) {
    content = `${body}\nКОНТРОЛЬНАЯ СУММА\nSHA-256: недоступно (Web Crypto)\n`;
  }
  downloadTextFile(`${c.id}-paket-nadzor.txt`, appendDemoExportSignatureBlock(content));
  pushAuditEntry('Экспорт пакета надзор/суд', c.id, 'ПОЛ-004');
  pushCaseProvenance(caseId, { type: 'export', source: 'Экспорт', detail: 'Пакет для надзора / суда (SHA-256)', policy: 'ПОЛ-004' });
  addEvidenceCustodyExportEntries(caseId, 'Экспорт пакета надзор/суд (SHA-256)');
  if (document.getElementById('case-detail-root')?.querySelector('.evidence-custody-panel')) renderCaseDetail(caseId);
  refreshHeaderChrome();
  showToast(`Пакет сохранён: ${sanitizeDownloadFilename(`${c.id}-paket-nadzor.txt`)}`);
}

function exportAuditLogCsv() {
  if (!canAccessAuditJournal()) {
    showToast('ПОЛ-008: журнал аудита доступен только тех. администратору ЦОД.');
    return;
  }
  const rows = filterAuditLogRows(getAdminAuditLogSource());
  if (!rows.length) {
    showToast('Нет записей для экспорта по выбранным фильтрам.');
    return;
  }
  const esc = v => `"${String(v).replace(/"/g, '""')}"`;
  const body = rows.map(r => [r.time, r.user, r.action, r.object, r.policy].map(esc).join(';')).join('\n');
  downloadTextFile(`epsok-audit-${Date.now()}.csv`, `Время;Пользователь;Действие;Объект;Политика\n${body}`, 'text/csv;charset=utf-8');
  pushAuditEntry('Экспорт журнала', `${rows.length} записей`, 'ПОЛ-004');
  showToast(`Журнал аудита: ${rows.length} записей (CSV)`);
}

function csvEscapeCell(v) {
  return `"${String(v ?? '').replace(/"/g, '""')}"`;
}

function exportCasesRegistryCsv() {
  const rows = getFilteredCases();
  if (!rows.length) {
    showToast('Нет дел для экспорта в выборке.');
    return;
  }
  const p = getActivePersona();
  const header = 'Номер;Уровень;Статья;Статус;Этап;Ведомство;Ответственный;Срок;Регион';
  const body = rows.map(c => [
    c.id,
    REQUEST_SCOPES[getCaseJurisdictionScope(c, p)]?.label || '',
    c.article,
    caseStatusLabels[c.status] || c.status,
    c.stage,
    c.agencyName,
    getCaseManagersDisplay(c.id).join(', ') || c.lead,
    c.daysLeft != null ? `${c.daysLeft} дн.` : '',
    c.region
  ].map(csvEscapeCell).join(';')).join('\n');
  downloadTextFile(`epsok-cases-${Date.now()}.csv`, `${header}\n${body}`, 'text/csv;charset=utf-8');
  pushAuditEntry('Экспорт реестра дел', `${rows.length} записей`, 'ПОЛ-004');
  showToast(`Реестр: ${rows.length} дел (CSV)`);
}

function exportRequestsCsv() {
  const p = getActivePersona();
  const rows = getFilteredRequests();
  if (!rows.length) {
    showToast('Нет запросов для экспорта в выборке.');
    return;
  }
  const blind = isExecutorBlindContour(p);
  const header = 'ID;Уровень;Тип;Объект;Кому;От кого;Статус;Отправлен;SLA';
  const body = rows.map(r => {
    const subject = blind ? 'скрыто' : (r.subject || '—');
    const from = blind ? 'скрыто' : r.from;
    const sla = isRequestSlaOverdue(r) ? 'просрочено' : 'в норме';
    return [
      r.id,
      REQUEST_SCOPES[r.scope]?.label || r.scope,
      r.type,
      subject,
      formatRequestTarget(r),
      from,
      requestStatusLabels[r.status] || r.status,
      r.sent || '—',
      sla
    ].map(csvEscapeCell).join(';');
  }).join('\n');
  downloadTextFile(`epsok-requests-${Date.now()}.csv`, `${header}\n${body}`, 'text/csv;charset=utf-8');
  pushAuditEntry('Экспорт запросов', `${rows.length} записей`, 'ПОЛ-004');
  showToast(`Запросы: ${rows.length} записей (CSV)`);
}

function buildGraphPathReportText() {
  if (!graphPathState.pathNodeIds?.length) return '';
  const c = getCaseById(activeGraphCaseId);
  const lines = [
    'ЕПСОК · ПУТЬ НА ГРАФЕ СВЯЗЕЙ',
    '============================',
    `Дело: ${activeGraphCaseId || '—'}`,
    c ? `Статья: ${c.article} · ${c.crimeType}` : '',
    `Узлов: ${graphPathState.pathNodeIds.length} · Рёбер: ${graphPathState.pathEdges?.length || 0}`,
    `Сформировано: ${new Date().toLocaleString('ru-RU')}`,
    '',
    'МАРШРУТ'
  ];
  graphPathState.pathNodeIds.forEach((id, i) => {
    const n = graphNodes.find(x => x.id === id);
    lines.push(`${i + 1}. ${n ? getGraphCanvasLabel(n) : id}`);
  });
  return lines.filter(Boolean).join('\n');
}

async function copyGraphPathReport() {
  const text = buildGraphPathReportText();
  if (!text) {
    showToast('Сначала найдите путь между двумя узлами.');
    return;
  }
  try {
    if (!navigator.clipboard?.writeText) throw new Error('no-clipboard');
    await navigator.clipboard.writeText(text);
    pushAuditEntry('Копирование пути графа', activeGraphCaseId || '—', 'ПОЛ-004');
    showToast('Путь скопирован в буфер обмена.');
  } catch {
    showToast('Не удалось скопировать — используйте «Отчёт (TXT)».');
  }
}

function downloadGraphPathReportTxt() {
  const body = buildGraphPathReportText();
  if (!body) {
    showToast('Сначала найдите путь между двумя узлами.');
    return;
  }
  const fname = `${activeGraphCaseId || 'graph'}-path.txt`;
  downloadTextFile(fname, appendDemoExportSignatureBlock(body));
  pushAuditEntry('Экспорт пути графа', activeGraphCaseId || '—', 'ПОЛ-004');
  showToast(`Отчёт сохранён: ${sanitizeDownloadFilename(fname)}`);
}

function buildCaseActivityFeedDocument(caseId, filter = caseActivityFilter) {
  const c = getCaseById(caseId);
  if (!c) return '';
  const feed = filterCaseActivityItems(buildCaseActivityFeed(caseId), filter);
  const lines = [
    'ЕПСОК · ЛЕНТА СОБЫТИЙ ДЕЛА',
    '==========================',
    `Дело: ${caseId}`,
    `Фильтр: ${filter}`,
    `Записей: ${feed.length}`,
    `Сформировано: ${new Date().toLocaleString('ru-RU')}`,
    ''
  ];
  feed.forEach((it, i) => {
    lines.push(`${i + 1}. [${it.at}] ${it.title}`);
    lines.push(`   ${it.text}`);
    if (it.actor) lines.push(`   ${it.actor}`);
    lines.push('');
  });
  return lines.join('\n');
}

function downloadCaseActivityFeedTxt(caseId) {
  const access = getCaseAccessMode(caseId);
  if (access.mode === 'denied') {
    showToast('ПОЛ-001: нет доступа к выгрузке.');
    return;
  }
  const feed = filterCaseActivityItems(buildCaseActivityFeed(caseId), caseActivityFilter);
  if (!feed.length) {
    showToast('Нет событий в выбранной категории.');
    return;
  }
  const body = buildCaseActivityFeedDocument(caseId);
  const fname = `${caseId}-activity.txt`;
  downloadTextFile(fname, appendDemoExportSignatureBlock(body));
  pushAuditEntry('Экспорт ленты событий', caseId, 'ПОЛ-004');
  showToast(`Лента сохранена: ${sanitizeDownloadFilename(fname)}`);
}

function exportOsintFindingsTxt() {
  const scanId = selectedOsintScanId;
  const scan = osintScans.find(s => s.id === scanId);
  const findings = osintFindingsByScan[scanId] || [];
  if (!scan || !findings.length) {
    showToast('Выберите завершённую проверку с находками.');
    return;
  }
  const lines = [
    'ЕПСОК · ОТЧЁТ OSINT',
    '====================',
    `Проверка: ${formatScanId(scanId)}`,
    `Цель: ${osintTargetTypeLabels[scan.targetType] || scan.targetType} · ${maskTarget(scan.targetType, scan.targetValue)}`,
    `Профиль: ${osintProfileLabels[scan.profile] || scan.profile}`,
    `Дело: ${scan.caseId || '—'}`,
    `Находок: ${findings.length}`,
    `Сформировано: ${new Date().toLocaleString('ru-RU')}`,
    ''
  ];
  findings.forEach((f, i) => {
    lines.push(`${i + 1}. ${osintTypeLabels[f.normalizedType] || f.normalizedType} · ${f.value}`);
    lines.push(`   Источник: ${osintModuleLabel(f.sourceModule)} · уверенность ${f.confidence}%`);
  });
  const fname = `${scanId}-osint-report.txt`;
  downloadTextFile(fname, appendDemoExportSignatureBlock(lines.join('\n')));
  pushAuditEntry('Экспорт OSINT-отчёта', scanId, 'ПОЛ-006');
  showToast(`Отчёт сохранён: ${sanitizeDownloadFilename(fname)}`);
}

function exportSupportTicketsCsv() {
  const tickets = loadSupportTickets();
  if (!tickets.length) {
    showToast('Нет обращений для экспорта.');
    return;
  }
  const header = 'Номер;Тема;Приоритет;SLA;Статус;Создано;Контакт';
  const body = tickets.map(t => [
    t.id, t.subject,
    { normal: 'обычный', high: 'высокий', critical: 'критичный' }[t.priority] || t.priority,
    t.sla,
    SUPPORT_TICKET_STATUS_LABELS[t.status] || t.status,
    t.createdAt,
    t.contact
  ].map(csvEscapeCell).join(';')).join('\n');
  downloadTextFile(`epsok-support-${Date.now()}.csv`, `${header}\n${body}`, 'text/csv;charset=utf-8');
  pushAuditEntry('Экспорт обращений', `${tickets.length} записей`, 'ПОЛ-005');
  showToast(`Обращения: ${tickets.length} (CSV)`);
}

async function copySupportTicketId(ticketId) {
  try {
    if (!navigator.clipboard?.writeText) throw new Error('no-clipboard');
    await navigator.clipboard.writeText(ticketId);
    showToast(`Номер ${ticketId} скопирован.`);
  } catch {
    showToast(ticketId);
  }
}

function exportStaffWorkloadCsv() {
  const p = getActivePersona();
  const metrics = getStaffWorkloadMetrics(p);
  if (!metrics.length) {
    showToast('Нет данных о нагрузке.');
    return;
  }
  const header = 'Следователь;Дела;Срочные;SLA просрочено;Статус';
  const body = metrics.map(m => [
    m.name, m.openCases, m.urgent, m.overdueSla, m.urgent > 5 ? 'перегруз' : 'норма'
  ].map(csvEscapeCell).join(';')).join('\n');
  downloadTextFile(`epsok-workload-${Date.now()}.csv`, `${header}\n${body}`, 'text/csv;charset=utf-8');
  pushAuditEntry('Экспорт нагрузки следователей', `${metrics.length} записей`, 'ПОЛ-004');
  showToast(`Нагрузка: ${metrics.length} следователей (CSV)`);
}

function exportDeadlinesContourCsv() {
  const cases = getDeadlinesCaseList();
  if (!cases.length) {
    showToast('Нет дел для экспорта.');
    return;
  }
  const header = 'Номер;Статья;Этап;Ответственный;Осталось дн.;Регион';
  const body = cases.map(c => [
    c.id, c.article, c.stage, c.lead,
    c.daysLeft != null ? c.daysLeft : '',
    c.region
  ].map(csvEscapeCell).join(';')).join('\n');
  downloadTextFile(`epsok-deadlines-${Date.now()}.csv`, `${header}\n${body}`, 'text/csv;charset=utf-8');
  pushAuditEntry('Экспорт сводки сроков', `${cases.length} дел`, 'ПОЛ-004');
  showToast(`Сроки: ${cases.length} дел (CSV)`);
}

function exportSuspectsCsv() {
  const rows = getVisibleSuspects();
  if (!rows.length) {
    showToast('Нет фигурантов в выборке.');
    return;
  }
  const header = 'ID;ФИО;Статус;Дело;Регион;Телефон';
  const body = rows.map(s => {
    const meta = getSuspectCaseMeta(s.caseId, s);
    return [
      s.id, getSuspectFullName(s), s.status, s.caseId, meta.region, s.phones || ''
    ].map(csvEscapeCell).join(';');
  }).join('\n');
  downloadTextFile(`epsok-suspects-${Date.now()}.csv`, `${header}\n${body}`, 'text/csv;charset=utf-8');
  pushAuditEntry('Экспорт фигурантов', `${rows.length} записей`, 'ПОЛ-004');
  showToast(`Фигуранты: ${rows.length} (CSV)`);
}

function downloadVictimNotificationsTxt(caseId) {
  const items = getVictimNotifications(caseId);
  if (!items.length) {
    showToast('Нет уведомлений для экспорта.');
    return;
  }
  const c = getCaseById(caseId);
  const lines = [
    'ЕПСОК · УВЕДОМЛЕНИЯ ПОТЕРПЕВШИХ',
    '============================',
    `Дело: ${caseId}`,
    c ? `Статья: ${c.article}` : '',
    `Записей: ${items.length}`,
    `Сформировано: ${new Date().toLocaleString('ru-RU')}`,
    ''
  ];
  items.forEach((vn, i) => {
    lines.push(`${i + 1}. [${vn.at}] ${vn.channel} · ${vn.recipient || vn.victim || '—'}`);
    lines.push(`   ${vn.message || vn.text || '—'}`);
    lines.push(`   Статус: ${vn.status} · ${vn.actor || '—'}`);
    lines.push('');
  });
  downloadTextFile(`${caseId}-victim-notifications.txt`, appendDemoExportSignatureBlock(lines.filter(Boolean).join('\n')));
  pushAuditEntry('Экспорт уведомлений потерпевших', caseId, 'ПОЛ-004');
  showToast(`Уведомления сохранены: ${sanitizeDownloadFilename(`${caseId}-victim-notifications.txt`)}`);
}

function buildEvidenceCustodyDocument(caseId) {
  const c = getCaseById(caseId);
  const items = getCaseEvidenceItems(caseId);
  if (!items.length) return '';
  const lines = [
    'ЕПСОК · ЦЕПОЧКА ХРАНЕНИЯ ДОКАЗАТЕЛЬСТВ',
    '====================================',
    `Дело: ${caseId}`,
    c ? `Статья: ${c.article}` : '',
    `Объектов: ${items.length}`,
    `Сформировано: ${new Date().toLocaleString('ru-RU')}`,
    ''
  ];
  items.forEach((ev, i) => {
    lines.push(`${i + 1}. ${ev.id} · ${ev.description}`);
    lines.push(`   Изъято: ${ev.seizedAt}`);
    lines.push(`   SHA-256: ${ev.hash}`);
    (ev.chain || []).forEach(ch => {
      lines.push(`   · ${ch.at} · ${ch.actor} → ${ch.to || '—'}: ${ch.action}`);
    });
    lines.push('');
  });
  return lines.join('\n');
}

function downloadEvidenceCustodyTxt(caseId) {
  const body = buildEvidenceCustodyDocument(caseId);
  if (!body) {
    showToast('Нет записей в цепочке хранения.');
    return;
  }
  downloadTextFile(`${caseId}-custody.txt`, appendDemoExportSignatureBlock(body));
  addEvidenceCustodyExportEntries(caseId, 'Экспорт цепочки хранения (TXT)');
  pushAuditEntry('Экспорт цепочки хранения', caseId, 'ПОЛ-004');
  if (document.getElementById('case-detail-root')?.querySelector('.evidence-custody-panel')) renderCaseDetail(caseId);
  showToast(`Цепочка хранения сохранена: ${sanitizeDownloadFilename(`${caseId}-custody.txt`)}`);
}

async function copyEvidenceCustodyHashes(caseId) {
  const items = getCaseEvidenceItems(caseId);
  if (!items.length) {
    showToast('Нет хешей для копирования.');
    return;
  }
  const text = items.map(ev => `${ev.id}\t${ev.hash}`).join('\n');
  try {
    if (!navigator.clipboard?.writeText) throw new Error('no-clipboard');
    await navigator.clipboard.writeText(text);
    showToast('SHA-256 скопированы в буфер обмена.');
  } catch {
    downloadTextFile(`${caseId}-hashes.txt`, text);
    showToast('Хеши сохранены в файл.');
  }
}

function saveSuspectsFiltersState() {
  try {
    localStorage.setItem(getFiltersStorageKey(SUSPECTS_FILTERS_STORAGE), JSON.stringify({
      search: suspectSearchQuery,
      region: suspectFilterRegion,
      status: suspectFilterStatus
    }));
  } catch { /* noop */ }
}

function loadSuspectsFiltersState() {
  try {
    const raw = localStorage.getItem(getFiltersStorageKey(SUSPECTS_FILTERS_STORAGE));
    if (!raw) return;
    const data = JSON.parse(raw);
    suspectSearchQuery = data.search || '';
    suspectFilterRegion = data.region || '';
    suspectFilterStatus = data.status || '';
  } catch { /* noop */ }
}

function saveAuditFiltersState() {
  try {
    localStorage.setItem(AUDIT_FILTERS_STORAGE, JSON.stringify({
      user: auditFilterUser,
      action: auditFilterAction,
      query: auditFilterQuery,
      period: auditFilterPeriod
    }));
  } catch { /* noop */ }
}

function loadAuditFiltersState() {
  try {
    const raw = localStorage.getItem(AUDIT_FILTERS_STORAGE);
    if (!raw) return;
    const data = JSON.parse(raw);
    auditFilterUser = data.user || '';
    auditFilterAction = data.action || '';
    auditFilterQuery = data.query || '';
    auditFilterPeriod = data.period || 'all';
  } catch { /* noop */ }
}

function exportProsecutorHealthCsv() {
  const rows = getProsecutorHealthRows();
  if (!rows.length) {
    showToast('Нет дел для экспорта в надзорной панели.');
    return;
  }
  const header = 'Дело;Срок УПК;Граф;Запросы;Риск';
  const body = rows.map(({ c, m }) => [
    c.id,
    m.daysLeft != null ? `${m.daysLeft} дн.` : '—',
    m.graphGap ? `пробел (${m.graphNodes})` : `${m.graphNodes} узл.`,
    m.requestBacklog || 0,
    m.deadlineRisk
  ].map(csvEscapeCell).join(';')).join('\n');
  downloadTextFile(`epsok-prosecutor-health-${Date.now()}.csv`, `${header}\n${body}`, 'text/csv;charset=utf-8');
  pushAuditEntry('Экспорт надзорной панели', `${rows.length} дел`, 'ПОЛ-004');
  showToast(`Надзор: ${rows.length} дел (CSV)`);
}

function exportCourtDashboardCsv() {
  const p = getActivePersona();
  const rows = getPersonaScopedCases(p).filter(c => c.status === 'court' || (c.daysLeft != null && c.daysLeft <= 14));
  if (!rows.length) {
    showToast('Нет дел в судебном контуре.');
    return;
  }
  const header = 'Дело;Статья;Статус;Срок;Риск';
  const body = rows.map(c => [
    c.id,
    c.article,
    caseStatusLabels[c.status] || c.status,
    c.daysLeft != null ? `${c.daysLeft} дн.` : '—',
    getCaseRiskLevel(c.id) || '—'
  ].map(csvEscapeCell).join(';')).join('\n');
  downloadTextFile(`epsok-court-${Date.now()}.csv`, `${header}\n${body}`, 'text/csv;charset=utf-8');
  pushAuditEntry('Экспорт судебного контура', `${rows.length} дел`, 'ПОЛ-004');
  showToast(`Суд: ${rows.length} дел (CSV)`);
}

function exportHorizonWatchlistTxt() {
  const watch = loadHorizonWatchlist();
  if (!watch.length) {
    showToast('Watchlist пуст — добавьте токен.');
    return;
  }
  const hits = getHorizonWatchHitCount();
  const lines = [
    'ЕПСОК · WATCHLIST «ГОРИЗОНТ»',
    '===========================',
    `Дело: ${activeHorizonCaseId || '—'}`,
    `Токенов: ${watch.length}`,
    `Совпадений: ${hits}`,
    `Сформировано: ${new Date().toLocaleString('ru-RU')}`,
    '',
    ...watch.map((t, i) => `${i + 1}. ${t}`)
  ];
  downloadTextFile(`epsok-horizon-watchlist-${Date.now()}.txt`, appendDemoExportSignatureBlock(lines.join('\n')));
  pushAuditEntry('Экспорт watchlist', `${watch.length} токенов`, 'ПОЛ-007');
  showToast('Watchlist сохранён (TXT)');
}

function downloadCaseTeamTxt(caseId) {
  const c = getCaseById(caseId);
  if (!c) return;
  if (!personaCanBrowseCase(caseId)) {
    showToast('ПОЛ-001: нет доступа.');
    return;
  }
  const team = c.team || [];
  const lines = [
    'ЕПСОК · СОСТАВ РАБОЧЕЙ ГРУППЫ',
    '============================',
    `Дело: ${caseId}`,
    `Статья: ${c.article}`,
    `Ответственный: ${c.lead}`,
    `Руководители: ${getCaseManagersDisplay(caseId).join(', ') || '—'}`,
    '',
    'СОСТАВ',
    ...team.map((m, i) => `${i + 1}. ${m.name} — ${m.role}`)
  ];
  downloadTextFile(`${caseId}-team.txt`, appendDemoExportSignatureBlock(lines.join('\n')));
  pushAuditEntry('Экспорт состава РГ', caseId, 'ПОЛ-004');
  showToast(`Состав сохранён: ${sanitizeDownloadFilename(`${caseId}-team.txt`)}`);
}

function exportClusterHubCsv(clusterId = activeClusterHubId) {
  const cases = getClusterCases(clusterId);
  const stats = getClusterEntityCount(clusterId);
  if (!cases.length) {
    showToast('Нет дел в кластере.');
    return;
  }
  const header = 'Дело;Регион;Статья;Ответственный;Этап';
  const body = cases.map(c => [
    c.id, c.region, c.article, c.lead, c.stage
  ].map(csvEscapeCell).join(';')).join('\n');
  const meta = `Кластер;${clusterId}\nДел;${stats.cases}\nРегионов;${stats.regions}\n\n${header}\n${body}`;
  downloadTextFile(`EPSOK-cluster-${clusterId.replace(/[^A-Za-zА-Яа-я0-9-]/g, '')}.csv`, meta, 'text/csv;charset=utf-8');
  pushAuditEntry('Экспорт кластера CSV', clusterId, 'ПОЛ-007');
  showToast(`Кластер ${clusterId}: ${cases.length} дел (CSV)`);
}

function downloadLegislationImpactTxt() {
  const impact = loadLegislationImpact();
  if (!impact?.cases?.length) {
    showToast('Нет данных о затронутых делах. Запустите «Проверить обновления» в регламентах.');
    return;
  }
  const lines = [
    'ЕПСОК · ОТЧЁТ О ЗАТРОНУТЫХ ДЕЛАХ',
    '================================',
    `Проверено: ${impact.checkedAt || '—'}`,
    `Затронуто дел: ${impact.cases.length}`,
    '',
    'ДЕЛА',
    ...impact.cases.map((c, i) => `${i + 1}. ${c.id} · ${c.article || '—'} · осталось ${c.daysLeft} дн.`)
  ];
  if (impact.updated?.length) {
    lines.push('', 'ОБНОВЛЁННЫЕ АКТЫ', ...impact.updated.map(u => `  · ${u.code || u.lawId} · ${u.revisionDate || ''}`));
  }
  downloadTextFile(`epsok-legislation-impact-${Date.now()}.txt`, appendDemoExportSignatureBlock(lines.join('\n')));
  pushAuditEntry('Экспорт отчёта законодательства', `${impact.cases.length} дел`, 'ПОЛ-002');
  showToast('Отчёт о законодательстве сохранён (TXT)');
}

async function copyProfileEmail() {
  const email = getCorporateEmail(getActivePersona()?.id);
  if (!email) {
    showToast('Корпоративная почта не указана.');
    return;
  }
  try {
    if (!navigator.clipboard?.writeText) throw new Error('no-clipboard');
    await navigator.clipboard.writeText(email);
    showToast(`Скопировано: ${email}`);
  } catch {
    showToast(email);
  }
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
let mailSearchQuery = '';
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
    <div class="mail-detail-actions">
      <button type="button" class="btn-sm" onclick="openMailCompose()">↩ Ответить</button>
      <button type="button" class="btn-sm" onclick="forwardCorpMailThread()">↪ Переслать</button>
      <button type="button" class="btn-sm" onclick="copyCorpMailThread()">Копировать</button>
      <button type="button" class="btn-sm" onclick="printCorpMailThread()">Печать</button>
    </div>
  </div>
  <div class="mail-messages">${blocks.join('')}</div>`;
}

function getCorpMailThreadMessages(threadId = activeMailThreadId) {
  const login = getCurrentMailLogin();
  const email = getCurrentMailEmail();
  const thr = corpMailThreads.find(t => t.id === threadId);
  if (!thr) return { thr: null, msgs: [] };
  const msgs = [];
  thr.messages.forEach(bundle => {
    bundle.copies.forEach(copy => {
      const inbox = copy.sealedFor === login && copy.to?.includes(email) && copy.folderCopy !== 'sent';
      const sent = copy.from === email && copy.folderCopy === 'sent' && copy.sealedFor === login;
      if ((mailFolder === 'inbox' && inbox) || (mailFolder === 'sent' && sent)) msgs.push(copy);
    });
  });
  msgs.sort((a, b) => (a.at || '').localeCompare(b.at || '', 'ru'));
  return { thr, msgs };
}

async function getCorpMailMessagePlaintext(msg) {
  if (!msg.bodySealed) return msg.plain || '—';
  try {
    return await mailOpen(
      msg.bodySealed,
      msg.sealedFor || getCurrentMailLogin(),
      mailLoginFromEmail(msg.from),
      msg.id,
      msg.classification || 'standard'
    );
  } catch {
    return '[ошибка расшифровки]';
  }
}

async function buildCorpMailThreadPlaintext(threadId = activeMailThreadId) {
  const { thr, msgs } = getCorpMailThreadMessages(threadId);
  if (!thr || !msgs.length) return '';
  const blocks = [];
  for (const msg of msgs) {
    const plain = await getCorpMailMessagePlaintext(msg);
    const contact = findMailContact(msg.from);
    blocks.push(`От: ${msg.fromName || contact.name} <${msg.from}>\nДата: ${msg.at}\nТема: ${msg.subject}\n\n${plain}`);
  }
  return `ЕПСОК · ПОЧТА\nТема: ${thr.subject}\n${'='.repeat(40)}\n\n${blocks.join('\n\n---\n\n')}`;
}

async function copyCorpMailThread() {
  const text = await buildCorpMailThreadPlaintext();
  if (!text) {
    showToast('Нет сообщения для копирования.');
    return;
  }
  try {
    if (!navigator.clipboard?.writeText) throw new Error('no-clipboard');
    await navigator.clipboard.writeText(text);
    pushAuditEntry('Копирование почты', activeMailThreadId || '—', 'ПОЛ-004');
    showToast('Сообщение скопировано в буфер обмена.');
  } catch {
    showToast('Не удалось скопировать.');
  }
}

async function printCorpMailThread() {
  const text = await buildCorpMailThreadPlaintext();
  if (!text) {
    showToast('Нет сообщения для печати.');
    return;
  }
  const w = window.open('', '_blank', 'noopener,noreferrer');
  if (!w) {
    showToast('Разрешите всплывающие окна для печати.');
    return;
  }
  w.document.write(`<!DOCTYPE html><html lang="ru"><head><meta charset="UTF-8"><title>Почта</title>
<style>body{font-family:'Segoe UI',system-ui,sans-serif;max-width:720px;margin:1.5rem auto;line-height:1.5;font-size:12pt}
pre{white-space:pre-wrap;font-family:inherit;margin:0}@media print{body{margin:0.8cm}}</style></head>
<body><pre>${escapeHtml(text)}</pre></body></html>`);
  w.document.close();
  w.focus();
  setTimeout(() => { try { w.print(); } catch { /* noop */ } }, 300);
  pushAuditEntry('Печать почты', activeMailThreadId || '—', 'ПОЛ-004');
  showToast('Диалог печати открыт');
}

async function forwardCorpMailThread() {
  const { thr, msgs } = getCorpMailThreadMessages();
  if (!thr || !msgs.length) {
    showToast('Нет сообщения для пересылки.');
    return;
  }
  const last = msgs[msgs.length - 1];
  const plain = await getCorpMailMessagePlaintext(last);
  const quote = `\n\n-------- Пересылаемое сообщение --------\nОт: ${last.from}\nДата: ${last.at}\nТема: ${last.subject}\n\n${plain}`;
  openMailCompose('', `Fwd: ${thr.subject}`, quote);
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
  const threadsAll = getMailThreadsGrouped();
  const q = mailSearchQuery.trim().toLowerCase();
  const threads = q
    ? threadsAll.filter(g => {
      const peer = mailFolder === 'sent' ? g.latest.to?.[0] : g.latest.from;
      const peerContact = findMailContact(peer);
      const hay = `${g.thread.subject} ${peerContact.name} ${peer}`.toLowerCase();
      return hay.includes(q);
    })
    : threadsAll;
  if (!activeMailThreadId && threads.length) activeMailThreadId = threads[0].thread.id;
  else if (activeMailThreadId && threads.length && !threads.some(g => g.thread.id === activeMailThreadId)) {
    activeMailThreadId = threads[0].thread.id;
  }

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
      <label class="mail-search-field">
        <span class="sr-only">Поиск по почте</span>
        <input type="search" id="mail-thread-search" class="mail-thread-search" placeholder="Тема, адресат…" value="${escapeHtml(mailSearchQuery)}" oninput="setMailSearchQuery(this.value)">
      </label>
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

function setMailSearchQuery(val) {
  mailSearchQuery = val;
  renderCorpMail();
}

function openMailCompose(to, subject, bodyPrefix) {
  const modal = document.getElementById('mail-compose-modal');
  const toEl = document.getElementById('mail-compose-to');
  const subEl = document.getElementById('mail-compose-subject');
  const bodyEl = document.getElementById('mail-compose-body');
  const caseLinkEl = document.getElementById('mail-compose-case-link');
  const caseLabelEl = document.getElementById('mail-compose-case-label');
  let replyTo = to;
  if (!replyTo && activeMailThreadId && bodyPrefix == null) {
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
  if (subEl) subEl.value = subject || (activeMailThreadId && bodyPrefix == null ? `Re: ${corpMailThreads.find(t => t.id === activeMailThreadId)?.subject || ''}` : '');
  if (bodyEl) bodyEl.value = bodyPrefix || '';
  if (caseLinkEl) {
    const canLink = activeCaseId && personaCanBrowseCase(activeCaseId);
    caseLinkEl.checked = !!canLink;
    caseLinkEl.disabled = !canLink;
  }
  if (caseLabelEl && activeCaseId) {
    caseLabelEl.textContent = personaCanBrowseCase(activeCaseId) ? activeCaseId : '—';
  }
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
  const linkCase = document.getElementById('mail-compose-case-link')?.checked;
  const caseRef = linkCase && activeCaseId && personaCanBrowseCase(activeCaseId) ? activeCaseId : null;
  if (!to || !subject || !body) return;

  const fromEmail = getCurrentMailEmail();
  const fromName = getActivePersona().name;
  const cls = MAIL_CLASSIFICATION[classification] || MAIL_CLASSIFICATION.standard;
  const bodyWithRef = caseRef ? `${body}\n\n—\nПривязка к делу: ${caseRef}` : body;
  const now = new Date();
  const at = `${String(now.getDate()).padStart(2, '0')}.${String(now.getMonth() + 1).padStart(2, '0')}.${now.getFullYear()} ${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}`;

  const raw = {
    id: `msg-${Date.now()}`,
    from: fromEmail,
    fromName,
    to: [to],
    at,
    subject,
    plain: bodyWithRef,
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
  if (caseRef) pushAuditEntry('Почта с привязкой к делу', `${caseRef} → ${to}`, 'ПОЛ-005');
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
  court: 'Направлено в суд',
  merged: 'Объединено',
  closed: 'Закрыто'
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
    ],
    victims: [{ name: '23 потерпевших', note: 'переводы по схеме «инвестиции»' }],
    figurants: [
      { name: 'Подозреваемый А.', role: 'основной фигурант' },
      { name: 'Алексей Петров', role: 'кандидат по OSINT', note: 'требует проверки' }
    ],
    keyObjects: [
      { type: 'account', label: 'Счёт ***8842', detail: 'получатель переводов · запрос РФМ исполнен' },
      { type: 'phone', label: '+7 (900) 123-45-67', detail: '847 исходящих за 30 дней' },
      { type: 'phone', label: '+7 (900) 987-89-01', detail: 'общая SIM с делом Казань' }
    ],
    legalBasis: 'материал проверки по заявлению · КУСП-1284/2028',
    registrationOrder: 'постановление о возбуждении №142 от 14.01.2028',
    proceduralStage: 'ст. 162 УПК · предварительное следствие',
    activeRequests: 5,
    osintChecks: 1
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
    related: [],
    victims: [{ name: 'Соколов В.И.', role: 'потерпевший', note: 'владелец угнанного ТС' }],
    figurants: [{ name: 'не установлен', role: 'подозреваемый', note: 'ориентировка ГИБДД · Краснодарский край' }],
    keyObjects: [
      { type: 'vehicle', label: 'Toyota Camry', detail: 'госномер К123АВ123 · угон 31.05.2028' },
      { type: 'phone', label: '+7 (918) 555-12-34', detail: 'контакт из объявления о продаже' }
    ],
    legalBasis: 'заявление потерпевшего · материал проверки КУСП-2847/2028',
    registrationOrder: 'постановление о возбуждении №47 от 01.06.2028',
    proceduralStage: 'ст. 162 УПК · предварительное следствие',
    activeRequests: 2,
    osintChecks: 1
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
  return !isCaseReadOnly(p, caseId) && isCaseManager(p.id, caseId);
}

function isCaseLead(personaId, caseId) {
  const c = getCaseById(caseId);
  const p = demoPersonas[personaId];
  if (!c || !p) return false;
  if (c.lead && p.name === c.lead) return true;
  if (findPersonaIdByLeadName(c.lead) === personaId) return true;
  return (c.team || []).some(m => m.name === p.name && /ответственн/i.test(m.role));
}

function canEditCaseTeam(caseId, p = getActivePersona()) {
  if (isCaseReadOnly(p, caseId)) return false;
  return isCaseManager(p.id, caseId) || isCaseLead(p.id, caseId) || isBetaRootPersona(p);
}

const CASE_TEAM_ROLES = [
  'следователь (соисполнитель)',
  'оперуполномоченный',
  'следователь',
  'дознаватель',
  'следователь (консультант)',
  'следователь СК (смежное дело)',
  'руководитель ОУР'
];

const CASE_REGISTRY_STORAGE = 'epsok-cases-registry-v1';

function saveCasesRegistry() {
  try {
    const patch = casesRegistry.map(c => ({
      id: c.id,
      team: c.team,
      managers: c.managers,
      lead: c.lead,
      daysLeft: c.daysLeft,
      timeline: c.timeline
    }));
    localStorage.setItem(CASE_REGISTRY_STORAGE, JSON.stringify(patch));
  } catch (_) { /* demo */ }
}

function loadCasesRegistryOverrides() {
  try {
    const raw = localStorage.getItem(CASE_REGISTRY_STORAGE);
    if (!raw) return;
    JSON.parse(raw).forEach(ov => {
      const c = getCaseById(ov.id);
      if (!c) return;
      if (ov.team) c.team = ov.team;
      if (ov.managers) c.managers = ov.managers;
      if (ov.lead) c.lead = ov.lead;
      if (ov.daysLeft != null) c.daysLeft = ov.daysLeft;
      if (ov.timeline) c.timeline = ov.timeline;
    });
  } catch (_) { /* demo */ }
}

function countResponsibleTeamMembers(c) {
  return (c.team || []).filter(m => /ответственн/i.test(m.role)).length;
}

function getCaseTeamPersonnelPool(caseId) {
  const c = getCaseById(caseId);
  if (!c) return [];
  const existing = new Set((c.team || []).map(m => m.name));
  return Object.entries(demoPersonas)
    .filter(([, p]) => {
      if (!['inv', 'inv_lead', 'ops'].includes(p.roleType)) return false;
      if (c.agency && p.agency !== c.agency) return false;
      if (c.region && p.region !== c.region) return false;
      if (existing.has(p.name)) return false;
      return true;
    })
    .map(([id, p]) => ({ id, name: p.name, department: p.department || p.role }))
    .sort((a, b) => a.name.localeCompare(b.name, 'ru'));
}

function canRemoveCaseTeamMember(caseId, index, p = getActivePersona()) {
  const c = getCaseById(caseId);
  if (!c || !canEditCaseTeam(caseId, p)) return false;
  const member = c.team?.[index];
  if (!member) return false;
  if (/ответственн/i.test(member.role) && countResponsibleTeamMembers(c) <= 1) return false;
  return true;
}

let caseTeamModalCaseId = null;

function openCaseTeamAddModal(caseId) {
  if (!canEditCaseTeam(caseId)) {
    showToast('Изменение состава доступно ответственному и руководителям дела (ПОЛ-001).');
    return;
  }
  caseTeamModalCaseId = caseId;
  const pool = getCaseTeamPersonnelPool(caseId);
  const select = document.getElementById('case-team-add-person');
  if (select) {
    select.innerHTML = pool.length
      ? `<option value="">Выберите сотрудника…</option>${pool.map(x =>
        `<option value="${x.id}">${escapeHtml(x.name)} · ${escapeHtml(x.department)}</option>`
      ).join('')}`
      : '<option value="">Нет доступных сотрудников в регионе</option>';
  }
  const roleSel = document.getElementById('case-team-add-role');
  if (roleSel) {
    roleSel.innerHTML = CASE_TEAM_ROLES.map(r => `<option value="${escapeHtml(r)}">${escapeHtml(r)}</option>`).join('');
  }
  document.getElementById('case-team-modal-case-id').value = caseId;
  document.getElementById('case-team-modal')?.classList.remove('hidden');
}

function closeCaseTeamAddModal() {
  document.getElementById('case-team-modal')?.classList.add('hidden');
  caseTeamModalCaseId = null;
}

function parsePersonaNameParts(name) {
  const parts = String(name || '').trim().split(/\s+/);
  const lastName = parts[0] || '';
  const firstInitial = (parts[1] || '').replace(/\./g, '').charAt(0).toUpperCase();
  return { lastName, firstInitial };
}

function findTeamPersonaConflict(caseId, persona) {
  const { lastName, firstInitial } = parsePersonaNameParts(persona?.name);
  if (!lastName) return null;
  return suspectDossiers.find(d => {
    if (d.caseId !== caseId || !['подозреваемый', 'потерпевший', 'обвиняемый'].includes(d.status)) return false;
    if (d.lastName !== lastName) return false;
    if (!firstInitial || !d.firstName) return true;
    return d.firstName.charAt(0).toUpperCase() === firstInitial;
  }) || null;
}

function submitCaseTeamAdd() {
  const caseId = document.getElementById('case-team-modal-case-id')?.value || caseTeamModalCaseId;
  if (!caseId || !canEditCaseTeam(caseId)) return;
  const personaId = document.getElementById('case-team-add-person')?.value;
  const role = document.getElementById('case-team-add-role')?.value;
  if (!personaId) { showToast('Выберите сотрудника.'); return; }
  const persona = demoPersonas[personaId];
  if (!persona) return;
  const conflict = findTeamPersonaConflict(caseId, persona);
  if (conflict) {
    pushAuditEntry('Блокировка РГ: конфликт интересов', `${caseId} · ${persona.name}`, 'ПОЛ-001');
    showToast(`Конфликт интересов: ${persona.name} совпадает с ${conflict.status} по делу. Добавление заблокировано (ПОЛ-001).`);
    return;
  }
  const c = getCaseById(caseId);
  c.team = c.team || [];
  if (c.team.some(m => m.name === persona.name)) {
    showToast('Сотрудник уже в составе рабочей группы.');
    return;
  }
  c.team.push({ name: persona.name, role: role || CASE_TEAM_ROLES[0], personaId });
  saveCasesRegistry();
  appendCaseTimelineEntry(caseId, `В рабочую группу включён ${persona.name} (${role})`);
  pushCaseProvenance(caseId, { type: 'team', source: 'Рабочая группа', detail: `Включён ${persona.name} · ${role}`, policy: 'ПОЛ-001' });
  closeCaseTeamAddModal();
  showToast(`${persona.name} добавлен в состав`);
  renderCaseDetail(caseId);
}

function removeCaseTeamMember(caseId, index) {
  const c = getCaseById(caseId);
  const member = c?.team?.[index];
  if (!member || !canRemoveCaseTeamMember(caseId, index)) {
    const p = getActivePersona();
    if (member?.name === p.name && /ответственн/i.test(member.role)) {
      showToast('Нельзя исключить себя — вы единственный ответственный по делу.');
    } else {
      showToast('Нельзя исключить единственного ответственного по делу.');
    }
    return;
  }
  c.team.splice(index, 1);
  saveCasesRegistry();
  appendCaseTimelineEntry(caseId, `Исключён из рабочей группы: ${member.name}`);
  showToast(`${member.name} исключён из состава`);
  renderCaseDetail(caseId);
}

function renderCaseTeamSection(c) {
  const canEdit = canEditCaseTeam(c.id);
  const itemsHtml = (c.team || []).map((m, i) => {
    const removeBtn = canEdit && canRemoveCaseTeamMember(c.id, i)
      ? `<button type="button" class="btn-xs reject case-team-remove" onclick="removeCaseTeamMember('${c.id}',${i})" title="Исключить из состава">✕</button>`
      : '';
    return `<li class="case-team-item">
      <div class="case-team-main"><strong>${escapeHtml(m.name)}</strong> — ${escapeHtml(m.role)}</div>
      ${removeBtn}
    </li>`;
  }).join('');

  const managersHint = getCaseManagersDisplay(c.id).join(', ') || c.lead || '—';
  const editBlock = canEdit
    ? `<div class="case-team-edit">
        <p class="muted case-team-edit-hint">Вы — ответственный / руководитель дела · можно менять состав рабочей группы</p>
        <div class="case-team-actions">
          <button type="button" class="btn-sm" onclick="downloadCaseTeamTxt('${c.id}')">TXT</button>
          <button type="button" class="btn-sm" onclick="openCaseTeamAddModal('${c.id}')">Изменить состав</button>
        </div>
      </div>`
    : `<div class="case-team-readonly">
        <p class="muted case-team-readonly-hint">Только просмотр · изменять состав могут руководители дела: ${escapeHtml(managersHint)}</p>
        <button type="button" class="btn-sm" onclick="downloadCaseTeamTxt('${c.id}')">TXT</button>
      </div>`;

  return `
    <h2>Рабочая группа</h2>
    <ul class="team-list case-team-list">${itemsHtml || '<li class="muted">Состав не указан</li>'}</ul>
    ${editBlock}
  `;
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

function openCaseTimelineNoteModal(caseId) {
  if (!personaCanAccessCase(caseId) || isCaseReadOnly()) {
    showToast('ПОЛ-001: нет прав на запись в хронологию.');
    return;
  }
  activeTimelineNoteCaseId = caseId;
  const ta = document.getElementById('case-timeline-note-text');
  if (ta) ta.value = '';
  document.getElementById('case-timeline-note-modal')?.classList.remove('hidden');
}

function closeCaseTimelineNoteModal() {
  activeTimelineNoteCaseId = null;
  document.getElementById('case-timeline-note-modal')?.classList.add('hidden');
}

function submitCaseTimelineNote(e) {
  e.preventDefault();
  const caseId = activeTimelineNoteCaseId;
  const text = document.getElementById('case-timeline-note-text')?.value.trim();
  if (!caseId || !text) return;
  appendCaseTimelineEntry(caseId, text, { manual: true, highlight: true });
  pushAuditEntry('Запись в хронологию', `${caseId} · ${text.slice(0, 48)}`, 'ПОЛ-005');
  pushCaseProvenance(caseId, { type: 'timeline', source: 'Хронология', detail: text, policy: 'ПОЛ-005' });
  closeCaseTimelineNoteModal();
  showToast('Запись добавлена в хронологию дела');
}

let activeTimelineNoteCaseId = null;

let demoCaseSeq = 99100;

function getPersonaCaseAgency(p) {
  if (!p) return null;
  const scope = p.caseScope || {};
  if (scope.agency) {
    const fromScope = getAgencyByCaseCode(scope.agency);
    if (fromScope) return fromScope;
  }
  const agencyKey = getPersonaAgencyKey(p);
  return agencyRegistry.find(a => a.id === agencyKey) || null;
}

function syncNewCaseAgencyField(p) {
  const select = document.getElementById('new-case-agency');
  const agency = getPersonaCaseAgency(p);
  if (!select) return null;
  if (!agency) {
    select.innerHTML = '';
    select.disabled = true;
    return null;
  }
  select.innerHTML = `<option value="${agency.caseCode}">${escapeHtml(agency.name)}</option>`;
  select.value = agency.caseCode;
  select.disabled = true;
  select.title = 'Ведомство определяется вашей ролью (ПОЛ-001)';
  return agency.caseCode;
}

function canCreateCase() {
  const p = getActivePersona();
  return getAgencyPolicy(p).canCreate === true && !!getPersonaCaseAgency(p);
}

function openNewCaseModal() {
  if (!canCreateCase()) {
    showToast('Создание дела доступно следователю и дознавателю своего ведомства.');
    return;
  }
  const p = getActivePersona();
  const scope = p.caseScope || {};
  document.getElementById('new-case-region').value = scope.region || p.region || '';
  document.getElementById('new-case-department').value = scope.department || p.department || '';
  syncNewCaseAgencyField(p);
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
  const expectedAgency = getPersonaCaseAgency(p);
  const crimeType = document.getElementById('new-case-crime')?.value.trim();
  const article = document.getElementById('new-case-article')?.value.trim() || '159.3 УК РФ';
  const scope = p.caseScope || {};
  const region = document.getElementById('new-case-region')?.value.trim() || scope.region || p.region || 'Краснодарский край';
  const department = document.getElementById('new-case-department')?.value.trim() || scope.department || p.department || 'СО №3';
  const agencyCode = document.getElementById('new-case-agency')?.value;
  if (!expectedAgency || agencyCode !== expectedAgency.caseCode) {
    showToast('ПОЛ-001: дело можно возбудить только в своём ведомстве.');
    return;
  }
  if (!crimeType) { showToast('Укажите краткое описание состава преступления.'); return; }
  demoCaseSeq += 1;
  const id = `ЕПСОК-2028-${String(demoCaseSeq).slice(-6)}`;
  const newCase = {
    id,
    region,
    department,
    agency: expectedAgency.caseCode,
    agencyName: expectedAgency.name,
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

function getDeadlinesCaseList() {
  const scoped = getPersonaScopedCases().filter(isOpenCase);
  const extras = [];
  [activeDeadlinesCaseId, activeCaseId].forEach(id => {
    const c = getCaseById(id);
    if (c && isOpenCase(c) && personaCanBrowseCase(id) && !scoped.some(x => x.id === id)) extras.push(c);
  });
  return [...extras, ...scoped];
}

function renderDeadlines() {
  const root = document.getElementById('deadlines-root');
  if (!root) return;
  const cases = getDeadlinesCaseList();
  if (!activeDeadlinesCaseId || !cases.some(c => c.id === activeDeadlinesCaseId)) {
    activeDeadlinesCaseId = activeCaseId && cases.some(c => c.id === activeCaseId) ? activeCaseId : cases[0]?.id;
  }
  const c = getCaseById(activeDeadlinesCaseId);
  if (!c) {
    root.innerHTML = '<div class="panel"><p class="muted">Нет дел для контроля сроков в вашем контуре.</p></div>';
    return;
  }
  const browseOnly = !personaCanAccessCase(c.id);
  const cards = getCaseDeadlines(c.id).map(d => `
    <div class="deadline-card ${d.level}">
      <div class="dl-type">${escapeHtml(d.type)}</div>
      <div class="dl-article">${escapeHtml(d.article)}${d.limit ? ` · ${escapeHtml(d.limit)}` : ''}</div>
      <div class="dl-bar"><div class="dl-fill ${d.level === 'ok' ? 'ok' : ''}" style="width:${d.pct || 0}%"></div></div>
      <div class="dl-info">${d.daysLeft != null ? `Осталось <strong>${d.daysLeft} дн.</strong>` : escapeHtml(d.expires)}${d.info ? ` · ${escapeHtml(d.info)}` : ''}</div>
      ${d.action ? `<div class="dl-action">${escapeHtml(d.action)}</div>` : ''}
    </div>`).join('');
  const deadlineActionBtns = [
    `<button type="button" class="btn-sm" onclick="openCase('${c.id}')">Карточка дела</button>`,
    renderDeadlineExtensionButton(c.id),
    `<button type="button" class="btn-sm" onclick="downloadDeadlinesReminder('${c.id}')">Напоминание (TXT)</button>`,
    `<button type="button" class="btn-sm" onclick="exportDeadlinesContourCsv()">Сводка (CSV)</button>`,
    canAccessView('graph') ? `<button type="button" class="btn-sm" onclick="openCaseGraph('${c.id}')">Граф связей</button>` : '',
    canAccessView('horizon') ? `<button type="button" class="btn-sm" onclick="selectHorizonCase('${c.id}');showView('horizon')">Горизонт</button>` : ''
  ].filter(Boolean).join('');
  root.innerHTML = `
    ${browseOnly ? renderCaseReadonlyBanner(c.id) : ''}
    <div class="deadlines-toolbar panel action-toolbar">
      <div class="action-toolbar__row action-toolbar__picker">
        <label class="field case-picker-field">
          <span>Дело</span>
          <select id="deadlines-case-picker" onchange="selectDeadlinesCase(this.value)">
            ${cases.map(x => `<option value="${x.id}" ${x.id === c.id ? 'selected' : ''}>${x.id} · ${escapeHtml(x.article)}</option>`).join('')}
          </select>
        </label>
      </div>
      <div class="action-toolbar__row deadlines-summary">
        <span class="badge ${c.status}">${caseStatusLabels[c.status]}</span>
        <span class="muted">${escapeHtml(c.lead)} · ${escapeHtml(c.opened)}</span>
        ${c.daysLeft != null ? `<span class="cases-deadline ${c.daysLeft <= 3 ? 'critical' : c.daysLeft <= 7 ? 'warning' : ''}">${c.daysLeft} дн. до ключевого срока</span>` : ''}
      </div>
      <div class="action-toolbar__row action-toolbar__actions">${deadlineActionBtns}</div>
      <div class="action-toolbar__row deadlines-view-toggle">
        <button type="button" class="btn-sm${deadlinesViewMode === 'list' ? ' active' : ''}" onclick="toggleDeadlinesViewMode('list')">Список</button>
        <button type="button" class="btn-sm${deadlinesViewMode === 'calendar' ? ' active' : ''}" onclick="toggleDeadlinesViewMode('calendar')">Календарь</button>
      </div>
    </div>
    ${deadlinesViewMode === 'calendar' ? renderDeadlinesCalendar() : ''}
    <div class="panel${deadlinesViewMode === 'calendar' ? ' hidden' : ''}">
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
  syncAppDeepLinkHash({ view: 'deadlines', caseId });
}

function downloadDeadlinesReminder(caseId) {
  const c = getCaseById(caseId);
  if (!c) return;
  if (!personaCanBrowseCase(caseId)) {
    showToast('ПОЛ-001: нет доступа к выгрузке.');
    return;
  }
  const deadlines = getCaseDeadlines(caseId);
  const body = `ЕПСОК · НАПОМИНАНИЯ ПО СРОКАМ УПК
========================================
Дело:          ${c.id}
Статья:        ${c.article}
Ответственный: ${c.lead}
Сформировано:  ${formatAuditTimestamp()}

СРОКИ
${deadlines.map((d, i) => `${i + 1}. ${d.type}
   ${d.article}${d.limit ? ' · ' + d.limit : ''}
   Осталось: ${d.daysLeft != null ? d.daysLeft + ' дн.' : d.expires || '—'}
   ${d.info || ''}${d.action ? '\n   Действие: ' + d.action : ''}`).join('\n\n') || '—'}

---
ПОЛ-005 · только для служебного пользования
`;
  downloadTextFile(`EPSOK-${c.id}-deadlines.txt`, body);
  pushAuditEntry('Экспорт напоминаний по срокам', c.id, 'ПОЛ-005');
  showToast(`Напоминания сохранены: EPSOK-${sanitizeDownloadFilename(c.id)}-deadlines.txt`);
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
  const pool = getCasesBrowsePool().filter(c => {
    if (c.region !== region) return false;
    if (agency && !isCasesFilterAll(agency) && c.agency !== agency) return false;
    return true;
  });
  return [...new Set(pool.map(c => c.department))].sort();
}

function getCasesCascadeOptions(region, agency) {
  let base = getCasesBrowsePool();
  const regions = [...new Set(base.map(c => c.region))].sort();
  const agencies = region ? getCaseFilterAgencies(region) : [];
  const departments = region && agency ? getCaseFilterDepartments(region, agency) : [];
  return { regions, agencies, departments };
}

function getFilteredCases() {
  const region = document.getElementById('cases-filter-region')?.value || '';
  const agency = document.getElementById('cases-filter-agency')?.value || '';
  const department = document.getElementById('cases-filter-department')?.value || '';

  let pool = getCasesBrowsePool();
  if (region) pool = pool.filter(c => c.region === region);
  if (agency && !isCasesFilterAll(agency)) pool = pool.filter(c => c.agency === agency);
  if (department && !isCasesFilterAll(department)) pool = pool.filter(c => c.department === department);
  if (casesBookmarkFilter) {
    const bookmarks = loadCaseBookmarks();
    pool = pool.filter(c => bookmarks.includes(c.id));
  }
  if (casesStatusFilter === 'urgent') {
    pool = pool.filter(c => c.daysLeft != null && c.daysLeft <= 7);
  } else if (casesStatusFilter !== 'all') {
    pool = pool.filter(c => c.status === casesStatusFilter);
  }
  const q = casesSearchQuery.trim().toLowerCase();
  if (q) {
    pool = pool.filter(c => {
      const hay = [
        c.id, c.article, c.crimeType, c.lead, c.cluster, c.stage,
        c.agencyName, c.region, c.department,
        getCaseManagersDisplay(c.id).join(' ')
      ].filter(Boolean).join(' ').toLowerCase();
      return hay.includes(q);
    });
  }
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
  const locks = getCasesRegistryFilterLocks();
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
    const scopeLabel = REQUEST_SCOPES[caseFilterScope]?.label || 'Все дела';
    if (!regionSel.value && !agencySel.value && !deptSel.value) {
      hint.textContent = `Уровень «${scopeLabel}» · уточните регион, ведомство или отдел при необходимости`;
    } else if (!regionSel.value) {
      hint.textContent = `Уровень «${scopeLabel}» · выберите регион для уточнения (${regions.length} доступно)`;
    } else if (!agencySel.value) {
      const withCases = agencies.filter(a => a.count > 0).length;
      hint.textContent = `Уровень «${scopeLabel}» · ведомство в «${regionSel.value}» — ${withCases} с делами или «Все ведомства»`;
    } else if (!deptSel.value) {
      hint.textContent = `Уровень «${scopeLabel}» · отдел для «${formatAgencyFilterLabel(agencySel.value)}» — ${departments.length} вариант(ов) или «Все отделы»`;
    } else {
      hint.textContent = `Уровень «${scopeLabel}» · ${regionSel.value} · ${formatAgencyFilterLabel(agencySel.value)} · ${formatDepartmentFilterLabel(deptSel.value)}`;
    }
  }
}

function populateCasesFilterSelects() {
  updateCasesFilterUI();
}

function renderCasesRegistryQuickActions(c, p) {
  const parts = [];
  if (canAccessView('graph', p)) {
    parts.push(`<button type="button" class="btn-xs cases-row-qa" onclick="openCaseGraph('${c.id}')" title="Граф связей">◎</button>`);
  }
  if (canAccessView('deadlines', p)) {
    parts.push(`<button type="button" class="btn-xs cases-row-qa" onclick="openCaseDeadlines('${c.id}')" title="Сроки УПК">⏱</button>`);
  }
  if (canViewOsint(p)) {
    parts.push(`<button type="button" class="btn-xs cases-row-qa" onclick="openCaseOsint('${c.id}')" title="OSINT">⌕</button>`);
  }
  parts.push(`<button type="button" class="btn-xs cases-row-qa" onclick="copyCaseReference('${c.id}')" title="Ссылка на дело">⎘</button>`);
  return `<div class="cases-row-actions">${parts.join('')}<button type="button" class="btn-sm cases-open-btn" onclick="openCase('${c.id}')">Открыть</button></div>`;
}

function renderCasesRegistryRow(c, p, { showDeptCol }) {
  const deadlineClass = c.daysLeft != null && c.daysLeft <= 3 ? 'critical' : c.daysLeft != null && c.daysLeft <= 7 ? 'warning' : '';
  const deadline = c.daysLeft != null ? `${c.daysLeft} дн.` : '—';
  const metaSub = showDeptCol
    ? `${escapeHtml(c.department)} · ${escapeHtml(c.region)}`
    : escapeHtml(c.region);
  const cells = [
    `<td class="case-id-cell">
      ${renderCaseBookmarkBtn(c.id)}
      <button type="button" class="case-link" onclick="openCase('${c.id}')">${c.id}</button>${renderCaseRiskBadge(c.id)}
      <span class="case-meta-sub">${metaSub}</span>
    </td>`,
    `<td>${renderRequestScopeBadge(getCaseJurisdictionScope(c, p))}</td>`,
    `<td>${escapeHtml(c.article.replace(' УК РФ', ''))}</td>`,
    `<td><span class="badge ${c.status}">${caseStatusLabels[c.status]}</span></td>`,
    `<td>${escapeHtml(c.stage)}</td>`,
    `<td>${escapeHtml(c.agencyName)}</td>`,
    `<td>${escapeHtml(getCaseManagersDisplay(c.id).join(', ') || c.lead)}</td>`,
    `<td><span class="cases-deadline ${deadlineClass}">${deadline}</span></td>`,
    `<td class="cases-action-col">${renderCasesRegistryQuickActions(c, p)}</td>`
  ];
  return `<tr>${cells.join('')}</tr>`;
}

const CASES_REGISTRY_HEADERS = [
  'Номер дела',
  'Уровень',
  'Статья',
  'Статус',
  'Этап',
  'Ведомство',
  'Ответственный',
  'Срок',
  ''
];

function syncCasesRegistryTableHead() {
  const headRow = document.querySelector('#cases-table thead tr');
  if (!headRow) return;
  headRow.innerHTML = CASES_REGISTRY_HEADERS.map(label =>
    label ? `<th>${label}</th>` : '<th class="cases-action-col" aria-label="Действия"></th>'
  ).join('');
}

function renderCasesRegistry() {
  tablePageRefresh.cases = renderCasesRegistry;
  populateCasesFilterSelects();
  const filtered = getFilteredCases();
  const browsePool = getCasesBrowsePool();
  const p = getActivePersona();
  const scopeCounts = { all: casesRegistry.length, interagency: 0, intra_agency: 0, intra_department: 0 };
  casesRegistry.forEach(c => {
    const s = getCaseJurisdictionScope(c, p);
    if (scopeCounts[s] != null) scopeCounts[s] += 1;
  });

  document.querySelectorAll('.cases-scope-tabs .req-scope-tab').forEach(btn => {
    const scope = btn.dataset.scope;
    const n = scope === 'all' ? scopeCounts.all : scopeCounts[scope];
    btn.classList.toggle('active', caseFilterScope === scope);
    const countEl = btn.querySelector('.req-tab-count');
    if (countEl) countEl.textContent = String(n ?? 0);
  });

  const scopedTotal = browsePool.length;
  const body = document.getElementById('cases-table-body');
  const title = document.getElementById('cases-results-title');
  const pill = document.getElementById('cases-total-pill');
  const emptyState = document.getElementById('cases-empty-state');
  const tableWrap = document.querySelector('.cases-table-wrap');
  const region = document.getElementById('cases-filter-region')?.value || '';
  const agency = document.getElementById('cases-filter-agency')?.value || '';
  const department = document.getElementById('cases-filter-department')?.value || '';
  const urgent = browsePool.filter(c => c.daysLeft != null && c.daysLeft <= 7).length;
  const scopeLabel = caseFilterScope === 'all' ? 'Все дела' : (REQUEST_SCOPES[caseFilterScope]?.label || 'Дела');

  const kpiTotal = document.getElementById('cases-kpi-total');
  const kpiShown = document.getElementById('cases-kpi-shown');
  const kpiUrgent = document.getElementById('cases-kpi-urgent');
  if (kpiTotal) kpiTotal.textContent = String(scopedTotal);
  if (kpiShown) kpiShown.textContent = String(filtered.length);
  if (kpiUrgent) kpiUrgent.textContent = String(urgent);

  if (!body) return;

  syncCasesRegistryTableHead();

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

  if (title) {
    if (department && !isCasesFilterAll(department)) {
      title.textContent = `${scopeLabel} · ${formatDepartmentFilterLabel(department)}`;
    } else if (agency && !isCasesFilterAll(agency)) {
      title.textContent = `${scopeLabel} · ${formatAgencyFilterLabel(agency)}`;
    } else if (region) {
      title.textContent = `${scopeLabel} · ${region}`;
    } else {
      title.textContent = scopeLabel;
    }
  }
  if (pill) pill.textContent = formatCasesCount(filtered.length);

  const bookmarkTab = document.getElementById('cases-bookmark-tab');
  const bookmarkCount = document.getElementById('cases-bookmark-count');
  if (bookmarkCount) bookmarkCount.textContent = String(loadCaseBookmarks().length);
  bookmarkTab?.classList.toggle('active', casesBookmarkFilter);

  document.querySelectorAll('.cases-status-chips .req-status-chip').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.status === casesStatusFilter);
  });
  const casesSearchEl = document.getElementById('cases-registry-search');
  if (casesSearchEl && document.activeElement !== casesSearchEl) {
    casesSearchEl.value = casesSearchQuery;
  }

  if (filtered.length === 0) {
    const msg = casesBookmarkFilter
      ? 'Нет избранных дел'
      : caseFilterScope === 'intra_agency'
      ? 'Нет дел ведомства в выбранной выборке'
      : `Нет дел: ${scopeLabel.toLowerCase()}`;
    const sub = casesBookmarkFilter
      ? 'Отметьте дела звёздочкой в реестре или на карточке'
      : caseFilterScope === 'all'
      ? 'Сбросьте фильтры или выберите другой уровень охвата'
      : 'Переключите уровень («Все» / «Межведомственные») или уточните фильтры';
    mountTablePagination('cases-pagination', { total: 0, pageSize: TABLE_PAGE_SIZE, key: 'cases' });
    showEmpty(msg, sub);
    return;
  }

  showTable();
  const meta = paginateList(filtered, 'cases', measureTablePageSize(
    document.querySelector('#view-cases .table-scroll-paged'),
    { rowHeight: 32, minRows: 14, maxRows: 55, reservedBottom: 48 }
  ));
  const showDeptCol = !department || isCasesFilterAll(department);
  body.innerHTML = meta.slice.map(c => renderCasesRegistryRow(c, p, { showDeptCol })).join('');
  mountTablePagination('cases-pagination', meta);
}

function applyCasesFilters() {
  resetTablePage('cases');
  renderCasesRegistry();
}

function onCasesFilterRegionChange() {
  resetTablePage('cases');
  const agencySel = document.getElementById('cases-filter-agency');
  const deptSel = document.getElementById('cases-filter-department');
  if (agencySel && !agencySel.classList.contains('cases-filter-locked')) agencySel.value = '';
  if (deptSel && !deptSel.classList.contains('cases-filter-locked')) deptSel.value = '';
  saveCasesFiltersState();
  renderCasesRegistry();
}

function onCasesFilterAgencyChange() {
  resetTablePage('cases');
  const deptSel = document.getElementById('cases-filter-department');
  if (deptSel && !deptSel.classList.contains('cases-filter-locked')) deptSel.value = '';
  saveCasesFiltersState();
  renderCasesRegistry();
}

function onCasesFilterDepartmentChange() {
  resetTablePage('cases');
  saveCasesFiltersState();
  renderCasesRegistry();
}

function resetCasesFilters() {
  resetTablePage('cases');
  casesSearchQuery = '';
  casesStatusFilter = 'all';
  casesBookmarkFilter = false;
  applyCaseFilterDefaults(caseFilterScope);
  saveCasesFiltersState();
  renderCasesRegistry();
}

function openCase(caseId) {
  if (!getCaseById(caseId)) {
    showToast('Дело не найдено в реестре.');
    return;
  }
  if (!personaCanBrowseCase(caseId)) {
    showToast('ПОЛ-001: нет доступа к этому делу для текущей роли.');
    return;
  }
  activeCaseId = caseId;
  activeDeadlinesCaseId = caseId;
  recordRecentCase(caseId);
  if (getCaseById(caseId)?.cluster || getCaseById(caseId)?.related?.length) activeHorizonCaseId = caseId;
  updateHeaderContext();
  showView('case');
}

function getCaseStatCounts(c) {
  return {
    requests: c.activeRequests ?? platformRequests.filter(r =>
      ['progress', 'submitted', 'draft'].includes(r.status) && r.from?.includes(c.department?.slice(0, 14) || '___')
    ).length,
    osint: c.osintChecks ?? osintScans.filter(s => s.caseId === c.id).length
  };
}

function renderCasePartiesHtml(parties) {
  return parties.map(p => `
    <li><strong>${escapeHtml(p.name)}</strong>${p.role ? ` · ${escapeHtml(p.role)}` : ''}${p.note ? ` — ${escapeHtml(p.note)}` : ''}</li>
  `).join('');
}

function renderCaseKeyObjectsHtml(objects) {
  const typeIcons = { vehicle: '⧉', account: '▣', phone: '☎' };
  return objects.map(o => `
    <li class="case-key-object">
      <span class="case-key-type" aria-hidden="true">${typeIcons[o.type] || '·'}</span>
      <span><strong>${escapeHtml(o.label)}</strong>${o.detail ? ` · ${escapeHtml(o.detail)}` : ''}</span>
    </li>`).join('');
}

function renderCaseOverviewHtml(c) {
  const stats = getCaseStatCounts(c);
  const dlClass = c.daysLeft != null && c.daysLeft <= 3 ? 'critical' : c.daysLeft != null && c.daysLeft <= 7 ? 'warning' : '';
  const partiesBlock = (c.victims?.length || c.figurants?.length) ? `
      <div class="panel">
        <h2>Участники</h2>
        ${c.victims?.length ? `<h3 class="case-subheading">Потерпевшие</h3><ul class="case-party-list">${renderCasePartiesHtml(c.victims)}</ul>` : ''}
        ${c.figurants?.length ? `<h3 class="case-subheading">Фигуранты</h3><ul class="case-party-list">${renderCasePartiesHtml(c.figurants)}</ul>` : ''}
      </div>` : '';
  const objectsBlock = (c.keyObjects?.length || c.legalBasis) ? `
      <div class="panel">
        ${c.keyObjects?.length ? `<h2>Ключевые объекты</h2><ul class="case-key-objects">${renderCaseKeyObjectsHtml(c.keyObjects)}</ul>` : ''}
        ${c.legalBasis ? `<h2 class="${c.keyObjects?.length ? 'case-subheading-spaced' : ''}">Основание</h2><p class="case-legal-basis">${escapeHtml(c.legalBasis)}</p>` : ''}
      </div>` : '';
  return `
    <div class="case-overview-grid panel">
      <div class="case-stat-card case-stat-card--deadline ${dlClass}">
        <span class="case-stat-label">Ключевой срок</span>
        <span class="case-stat-value">${c.daysLeft != null ? `${c.daysLeft} дн.` : '—'}</span>
        <span class="case-stat-sub">${escapeHtml(c.proceduralStage || c.stage)}</span>
      </div>
      <div class="case-stat-card">
        <span class="case-stat-label">Возбуждено</span>
        <span class="case-stat-value case-stat-value--sm">${escapeHtml(c.opened)}</span>
        ${c.registrationOrder ? `<span class="case-stat-sub">${escapeHtml(c.registrationOrder)}</span>` : ''}
      </div>
      <div class="case-stat-card">
        <span class="case-stat-label">Запросы</span>
        <span class="case-stat-value">${stats.requests}</span>
        <span class="case-stat-sub">активных</span>
      </div>
      <div class="case-stat-card">
        <span class="case-stat-label">OSINT</span>
        <span class="case-stat-value">${stats.osint}</span>
        <span class="case-stat-sub">проверок</span>
      </div>
      ${c.cluster ? `<div class="case-stat-card"><span class="case-stat-label">Кластер</span><span class="case-stat-value case-stat-value--sm">${escapeHtml(c.cluster)}</span></div>` : ''}
    </div>
    ${partiesBlock || objectsBlock ? `<div class="grid-2 case-facts-grid">${partiesBlock}${objectsBlock}</div>` : ''}
  `;
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

  const managersLabel = getCaseManagersDisplay(c.id);
  const managersHtml = managersLabel.length > 1
    ? `Руководители дела: ${escapeHtml(managersLabel.join(', '))}`
    : managersLabel.length === 1
      ? `Ответственный: ${escapeHtml(managersLabel[0])}`
      : `Ответственный: ${escapeHtml(c.lead)}`;

  const p = getActivePersona();
  const browseOnly = !personaCanAccessCase(c.id);
  const isProsecutor = ['prosecutor', 'prosecutor_mil'].includes(p.roleType) || isBetaRootPersona(p);
  const showExtension = !browseOnly && c.daysLeft != null && c.daysLeft <= 7 && canAccessView('deadlines', p);
  const showVictimNotif = !browseOnly && c.victims?.length && personaCanAccessCase(c.id);
  const graphRecsHtml = renderCaseGraphRecommendationsHtml(caseId);

  root.innerHTML = `
    ${renderCaseReadonlyBanner(caseId)}
    <nav class="case-breadcrumb" aria-label="Навигация по делу">
      <button type="button" class="case-breadcrumb-link" onclick="showView('cases')">Реестр дел</button>
      <span class="case-breadcrumb-sep" aria-hidden="true">/</span>
      <span class="case-breadcrumb-current">${escapeHtml(c.id)}</span>
    </nav>
    <div class="case-header-bar">
      <div class="case-header-row case-header-identity">
        <div class="case-header-main">
          ${renderCaseBookmarkBtn(caseId)}
          <span class="case-id">${c.id}</span>
          <span class="badge ${c.status}">${caseStatusLabels[c.status]}</span>
          ${renderCaseRiskBadge(caseId)}
          ${c.cluster ? `<button type="button" class="link-badge link-badge-btn" onclick="openClusterHub('${escapeHtml(c.cluster)}')">${escapeHtml(c.cluster)}</button>` : ''}
          <span class="link-badge">${countGraphNodesForCase(c.id)} узлов в графе</span>
        </div>
        ${renderCaseStatusWorkflowHtml(caseId)}
      </div>
      ${graphRecsHtml ? `<div class="case-header-row case-header-recs">${graphRecsHtml}</div>` : ''}
      <div class="case-header-row case-header-controls">
        ${renderCasePickerHtml(caseId)}
      </div>
      <div class="case-header-row case-header-actions">
        <div class="case-header-action-group">
          <span class="case-header-group-label">Выгрузки</span>
          <div class="case-header-btn-row">
            <button type="button" class="btn-sm" onclick="downloadCaseSummary('${caseId}')">Справка (TXT)</button>
            <button type="button" class="btn-sm" onclick="printCaseSummary('${caseId}')">Печать</button>
            <button type="button" class="btn-sm" onclick="copyCaseReference('${caseId}')" title="Скопировать ссылку на дело">Ссылка</button>
            <button type="button" class="btn-sm" onclick="downloadCaseCourtPackage('${caseId}')">Пакет надзор/суд</button>
            ${isProsecutor ? `<button type="button" class="btn-sm" onclick="downloadProsecutorSupervisionAct('${caseId}')">Акт надзора (TXT)</button>` : ''}
          </div>
        </div>
        ${(!browseOnly && (canCreateRequest() || showExtension || showVictimNotif)) ? `<div class="case-header-action-group">
          <span class="case-header-group-label">Действия</span>
          <div class="case-header-btn-row">
            ${!browseOnly && canCreateRequest() ? `<button type="button" class="btn-sm" onclick="openBatchRequestWizard('${caseId}')">Пакет запросов</button>` : ''}
            ${showExtension ? `<button type="button" class="btn-sm btn-warn" onclick="openDeadlineExtensionModal('${caseId}')">Ходатайство о продлении</button>` : ''}
            ${showVictimNotif ? `<button type="button" class="btn-sm" onclick="openVictimNotificationModal('${caseId}')">Уведомить потерпевшего</button>` : ''}
          </div>
        </div>` : ''}
      </div>
      <div class="case-header-row case-header-meta">
        <div class="case-meta">
          <span>${escapeHtml(c.article)} · ${escapeHtml(c.crimeType)}</span>
          <span>${escapeHtml(c.agencyName)} · ${escapeHtml(c.region)}</span>
          <span>${escapeHtml(c.department)}</span>
          <span>${managersHtml} · возбуждено ${escapeHtml(c.opened)}</span>
          ${c.daysLeft != null ? `<span class="cases-deadline ${c.daysLeft <= 7 ? 'warning' : ''}">Срок: ${c.daysLeft} дн.</span>` : ''}
        </div>
      </div>
    </div>
    ${renderCaseOverviewHtml(c)}
    ${renderCaseActivityFeedSection(c)}
    ${renderCaseEvidenceCustodySection(c)}
    ${renderCaseVictimNotificationsSection(c)}
    ${renderCaseProvenanceSection(c)}
    <div class="grid-2">
      <div class="panel">
        <div class="panel-header"><h2>Хронология</h2>
          ${!browseOnly && !isCaseReadOnly(p, caseId) ? `<button type="button" class="btn-sm" onclick="openCaseTimelineNoteModal('${caseId}')">+ Запись</button>` : ''}
        </div>
        <div class="timeline">${timelineHtml || '<p class="muted">Нет записей</p>'}</div>
      </div>
      <div class="panel">
        ${renderCaseTeamSection(c)}
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
  func_admin: { mode: 'none', canCreate: false },
  beta_root: { mode: 'initiator', hidden: [], canCreate: true }
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

function ensureActiveAgencyVisible(visibleList) {
  const visible = visibleList || getVisibleAgencies(getActivePersona());
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
  let visible = getVisibleAgencies(p);
  const q = agenciesSearchQuery.trim().toLowerCase();
  if (q) {
    visible = visible.filter(a => {
      const hay = [a.name, a.summary, a.law, agencyCategoryLabels[a.category], ...(a.functions || [])].join(' ').toLowerCase();
      return hay.includes(q);
    });
  }
  if (agenciesCategoryFilter) {
    visible = visible.filter(a => a.category === agenciesCategoryFilter);
  }
  ensureActiveAgencyVisible(visible);

  const ctx = document.getElementById('agencies-context');
  if (ctx) ctx.textContent = getAgenciesContextText(p);

  const kpiCount = document.getElementById('agencies-kpi-count');
  const kpiReq = document.getElementById('agencies-kpi-req');
  if (kpiCount) kpiCount.textContent = String(visible.length);
  if (kpiReq) {
    const reqCount = visible.reduce((n, a) => n + (isAgencySensitiveForPersona(a, p) ? 0 : (requestTypesByAgency[a.id] || []).length), 0);
    kpiReq.textContent = String(reqCount);
  }

  const searchEl = document.getElementById('agencies-search');
  if (searchEl && document.activeElement !== searchEl) searchEl.value = agenciesSearchQuery;
  const catEl = document.getElementById('agencies-category-filter');
  if (catEl) catEl.value = agenciesCategoryFilter;

  renderAgenciesNav(visible);
  renderAgencyDetail(activeAgencyId);
}

function setAgenciesSearch(query) {
  agenciesSearchQuery = query;
  renderAgencies();
}

function setAgenciesCategoryFilter(cat) {
  agenciesCategoryFilter = cat;
  renderAgencies();
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
  const pool = region
    ? getCasesBrowsePool().filter(c => {
      if (c.region !== region) return false;
      if (department && !isCasesFilterAll(department) && c.department !== department) return false;
      return true;
    })
    : [];
  const caseCounts = new Map();
  pool.forEach(c => caseCounts.set(c.agency, (caseCounts.get(c.agency) || 0) + 1));

  return agencyRegistry
    .filter(a => CASE_FILTER_AGENCY_CATEGORIES.includes(a.category))
    .map(a => ({
      code: a.caseCode,
      name: a.name,
      count: caseCounts.get(a.caseCode) || 0
    }))
    .filter(a => a.count > 0 || caseFilterScope === 'all');
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

const REQUEST_TEMPLATES_BY_ARTICLE = {
  '159.3': {
    label: '159.3 УК · мошенничество',
    scope: 'interagency',
    agency: 'FNS',
    type: 'FNS_INCOME_2NDFL',
    subject: '2-НДФЛ фигуранта · дело {caseId}'
  },
  '228.1': {
    label: '228.1 УК · наркотики',
    scope: 'interagency',
    agency: 'MVD',
    type: 'MVD_CDR',
    subject: 'Детализация связи абонента · дело {caseId}'
  },
  '105': {
    label: '105 УК · убийство',
    scope: 'interagency',
    agency: 'RFM',
    type: 'RFM_TRANSACTIONS',
    subject: 'Движение средств по счетам · дело {caseId}'
  },
  '272': {
    label: '272 УК · компьютерные преступления',
    scope: 'interagency',
    agency: 'FNS',
    type: 'FNS_ACCOUNT_INFO',
    subject: 'Сведения о счетах юрлица · дело {caseId}'
  }
};

function normalizeCaseArticleKey(article) {
  if (!article) return '';
  return String(article).replace(/\s*УК\s*РФ/i, '').trim();
}

function getRequestTemplatesForCase(caseId) {
  const c = caseId ? getCaseById(caseId) : null;
  if (!c) return [];
  const key = normalizeCaseArticleKey(c.article);
  const base = key.split(/\s/)[0];
  const matches = [];
  Object.entries(REQUEST_TEMPLATES_BY_ARTICLE).forEach(([art, tpl]) => {
    if (key.startsWith(art) || base === art || art.startsWith(base)) {
      matches.push({ art, ...tpl });
    }
  });
  return matches;
}

function populateRequestArticleTemplates(caseId) {
  const wrap = document.getElementById('req-template-wrap');
  const sel = document.getElementById('req-article-template');
  if (!wrap || !sel) return;
  const templates = getRequestTemplatesForCase(caseId || activeCaseId);
  wrap.classList.toggle('hidden', !templates.length);
  sel.innerHTML = templates.length
    ? `<option value="">— выберите шаблон —</option>${templates.map((t, i) =>
      `<option value="${i}">${escapeHtml(t.label)}</option>`
    ).join('')}`
    : '<option value="">— нет шаблона для статьи —</option>';
  sel.dataset.caseId = caseId || activeCaseId || '';
}

function applyRequestArticleTemplate() {
  const sel = document.getElementById('req-article-template');
  if (!sel || sel.value === '') return;
  const templates = getRequestTemplatesForCase(sel.dataset.caseId || activeCaseId);
  const tpl = templates[Number(sel.value)];
  if (!tpl) return;
  const caseId = sel.dataset.caseId || activeCaseId || '';
  const scopeSel = document.getElementById('req-scope');
  if (scopeSel) scopeSel.value = tpl.scope;
  const agencySel = document.getElementById('req-agency');
  if (agencySel && tpl.agency) agencySel.value = tpl.agency;
  updateRequestScopeFields();
  const typeSel = document.getElementById('req-type');
  if (typeSel && tpl.type && [...typeSel.options].some(o => o.value === tpl.type)) {
    typeSel.value = tpl.type;
    updateRequestLawRef();
  }
  const subjectInput = document.getElementById('req-subject');
  if (subjectInput) subjectInput.value = (tpl.subject || '').replace(/\{caseId\}/g, caseId);
}

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
let requestStatusFilter = 'all';
let caseFilterScope = 'intra_agency';
let requestSeq = 88512;
let activeFulfillRequestId = null;

function formatRequestNow() {
  const now = new Date();
  return `${String(now.getDate()).padStart(2, '0')}.${String(now.getMonth() + 1).padStart(2, '0')}.${now.getFullYear()} ${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}`;
}

function findExecutorPersonaId(r) {
  const haystack = `${r.target || ''} ${r.agency || ''} ${r.targetDepartment || ''}`.toLowerCase();
  for (const [id, p] of Object.entries(demoPersonas)) {
    if (p.roleType !== 'executor' || !p.execAgency) continue;
    const exec = p.execAgency.toLowerCase();
    const execShort = exec.split(/[\s(]/)[0];
    if (haystack.includes(exec) || haystack.includes(execShort) || r.target === p.execAgency) return id;
  }
  return null;
}

function getRequestById(id) {
  return platformRequests.find(r => r.id === id);
}

function isIncomingRequestForExecutor(r, p) {
  return p.dashboardMode === 'executor' && requestMatchesPersona(r, p) && (r.status === 'submitted' || r.status === 'progress');
}

function getPendingRequestCount(p = getActivePersona()) {
  if (p.dashboardMode === 'executor') {
    return platformRequests.filter(r => isIncomingRequestForExecutor(r, p)).length;
  }
  return platformRequests.filter(r =>
    r.requestorPersonaId === p.id && r.status === 'fulfilled' && r.resultUnread
  ).length;
}

function updateRequestsSidebarBadge() {
  const badge = document.getElementById('sidebar-requests-badge');
  if (!badge) return;
  const n = getPendingRequestCount();
  badge.textContent = String(n);
  badge.classList.toggle('hidden', n === 0);
}

async function pushEpsokSystemMail({ toPersonaId, subject, body }) {
  if (!toPersonaId) return;
  await ensureCorpMailReady();
  const toEmail = getCorporateEmail(toPersonaId);
  const raw = {
    id: `msg-sys-${Date.now()}`,
    from: 'integration@epsok.gov.ru',
    fromName: 'Запросы ЕПСОК · СМЭВ',
    to: [toEmail],
    at: formatRequestNow(),
    subject,
    plain: body,
    classification: 'official',
    keyId: 'SYS-SMEV',
    certFp: 'I4:N7…3B8C',
    read: false
  };
  const recipientCopy = await sealMailMessage(raw, toEmail);
  let thr = corpMailThreads.find(t => t.subject === subject);
  if (!thr) {
    thr = { id: `thr-req-${Date.now()}`, subject, messages: [] };
    corpMailThreads.unshift(thr);
  }
  thr.messages.push({ raw, copies: [recipientCopy] });
  await saveCorpMailState();
  updateMailSidebarBadge();
  updateRequestsSidebarBadge();
}

async function notifyRequestEvent(req, event) {
  if (event === 'created' && req.executorPersonaId) {
    const subjectLine = req.subject ? `\nОбъект: ${req.subject}` : '';
    await pushEpsokSystemMail({
      toPersonaId: req.executorPersonaId,
      subject: `[СМЭВ] Входящий запрос ${req.id}`,
      body: `Поступил запрос в вашу очередь исполнения.\n\nID: ${req.id}\nТип: ${req.type}${subjectLine}\nОт: ${req.from}\nКанал: ${REQUEST_SCOPES[req.scope]?.channel || 'СМЭВ'}\nОснование: ${req.legal || '—'}\n\nОткройте раздел «Запросы» → примите в работу и направьте результат инициатору.`
    });
  }
  if (event === 'fulfilled' && req.requestorPersonaId) {
    await pushEpsokSystemMail({
      toPersonaId: req.requestorPersonaId,
      subject: `[СМЭВ] Исполнен запрос ${req.id}`,
      body: `Запрос исполнен. Результат доступен в модуле «Запросы».\n\nID: ${req.id}\nТип: ${req.type}\nИсполнитель: ${req.target}\n\n${req.result || '—'}`
    });
  }
  updateRequestsSidebarBadge();
}

function renderRequestActions(r, p) {
  if (p.dashboardMode === 'executor' && requestMatchesPersona(r, p)) {
    if (r.status === 'submitted') {
      return `<button type="button" class="btn-xs approve" onclick="acceptRequest('${r.id}')">Принять</button>`;
    }
    if (r.status === 'progress') {
      return `<button type="button" class="btn-xs approve" onclick="openRequestFulfillModal('${r.id}')">Результат</button>`;
    }
  }
  if (r.requestorPersonaId === p.id && r.status === 'fulfilled' && r.result) {
    return `<button type="button" class="btn-xs" onclick="viewRequestResult('${r.id}')">Ответ</button>`;
  }
  if (r.requestorPersonaId === p.id && ['rejected', 'expired'].includes(r.status) && canCreateRequest(p)) {
    return `<button type="button" class="btn-xs approve" onclick="retryFailedRequest('${r.id}')">Повторить</button>`;
  }
  return '';
}

function acceptRequest(requestId) {
  const r = getRequestById(requestId);
  if (!r || getActivePersona().dashboardMode !== 'executor') return;
  r.status = 'progress';
  r.sla = 'в работе';
  renderRequests();
  renderExecutorDashboard(getActivePersona());
  updateRequestsSidebarBadge();
  showToast(`${requestId} принят в работу`);
}

function openRequestFulfillModal(requestId) {
  const r = getRequestById(requestId);
  if (!r) return;
  activeFulfillRequestId = requestId;
  const title = document.getElementById('request-fulfill-title');
  const hint = document.getElementById('request-fulfill-hint');
  const textarea = document.getElementById('request-fulfill-result');
  if (title) title.textContent = `Результат · ${r.id}`;
  if (hint) {
    const p = getActivePersona();
    if (isExecutorBlindContour(p)) {
      hint.textContent = `${r.type} · объект: ${redactRequestForExecutor(r, 'subject').replace(/<[^>]+>/g, '')} · основание: ${redactRequestForExecutor(r, 'legal').replace(/<[^>]+>/g, '')}`;
    } else {
      hint.textContent = `${r.type}${r.subject ? ` · ${r.subject}` : ''} · от ${r.from}`;
    }
  }
  if (textarea) textarea.value = r.result || '';
  document.getElementById('request-fulfill-modal')?.classList.remove('hidden');
}

function closeRequestFulfillModal() {
  activeFulfillRequestId = null;
  document.getElementById('request-fulfill-modal')?.classList.add('hidden');
}

async function submitRequestResultAsync() {
  const r = getRequestById(activeFulfillRequestId);
  const result = document.getElementById('request-fulfill-result')?.value.trim();
  if (!r) return;
  if (!result) {
    showToast('Укажите текст результата для инициатора.');
    return;
  }
  r.status = 'fulfilled';
  r.result = result;
  r.resultUnread = true;
  r.sla = 'исполнен ✓';
  r.fulfilledAt = formatRequestNow();
  closeRequestFulfillModal();
  pushAuditEntry('Результат запроса', r.id, 'ПОЛ-003');
  const provCaseId = activeCaseId || casesRegistry.find(c => r.subject?.includes(c.id))?.id;
  if (provCaseId) {
    const c = getCaseById(provCaseId);
    if (c?.daysLeft != null) {
      const shift = r.scope === 'interagency' ? 2 : 1;
      c.daysLeft += shift;
      appendCaseTimelineEntry(provCaseId, `Срок следствия продлён на ${shift} сут. (ст. 162/223 УПК · исполнен ${r.id})`);
      saveCasesRegistry();
      pushCaseProvenance(provCaseId, {
        type: 'timeline',
        source: 'УПК · сроки',
        detail: `+${shift} сут. после исполнения ${r.id} (${r.type})`,
        policy: 'ПОЛ-004'
      });
    }
    pushCaseProvenance(provCaseId, {
      type: 'result',
      source: 'Ответ на запрос',
      detail: `${r.id} · ${r.type} · ${(result || '').slice(0, 120)}${result.length > 120 ? '…' : ''}`,
      policy: 'ПОЛ-003'
    });
  }
  await notifyRequestEvent(r, 'fulfilled');
  renderRequests();
  renderExecutorDashboard(getActivePersona());
  if (document.getElementById('view-dashboard')?.classList.contains('active')) renderDashboard();
  showToast(`${r.id}: результат направлен инициатору · уведомление в корп. почте`);
}

function submitRequestResult() {
  return submitRequestResultAsync();
}

function viewRequestResult(requestId) {
  const r = getRequestById(requestId);
  if (!r?.result) return;
  activeRequestResultId = requestId;
  r.resultUnread = false;
  updateRequestsSidebarBadge();
  const title = document.getElementById('request-result-title');
  const meta = document.getElementById('request-result-meta');
  const body = document.getElementById('request-result-body');
  const dlBtn = document.getElementById('request-result-download');
  if (title) title.textContent = r.id;
  if (meta) meta.textContent = `${r.type} · ${r.target} · ${r.fulfilledAt || r.sent}`;
  if (body) body.textContent = r.result;
  if (dlBtn) dlBtn.classList.remove('hidden');
  document.getElementById('request-result-modal')?.classList.remove('hidden');
  renderRequests();
}

function closeRequestResultModal() {
  activeRequestResultId = null;
  document.getElementById('request-result-modal')?.classList.add('hidden');
}

function markOwnRequestResultsSeen() {
  const p = getActivePersona();
  platformRequests.forEach(r => {
    if (r.requestorPersonaId === p.id && r.status === 'fulfilled') r.resultUnread = false;
  });
  updateRequestsSidebarBadge();
}

function getDefaultCaseFilterScope(p = getActivePersona()) {
  if (!p || p.caseScope === null || p.dashboardMode === 'analyst') return 'all';
  return 'intra_agency';
}

function sameCaseAgency(c, p) {
  if (['prosecutor', 'prosecutor_mil', 'court'].includes(p.roleType)) {
    const region = p.caseScope?.region || p.region;
    return region ? c.region === region : true;
  }
  if (c.agency === p.agency) return true;
  const key = getPersonaAgencyKey(p);
  return c.agency === key;
}

function getCaseJurisdictionScope(c, p = getActivePersona()) {
  if (['prosecutor', 'prosecutor_mil', 'court'].includes(p.roleType)) {
    const region = p.caseScope?.region || p.region;
    if (region && c.region !== region) return 'interagency';
    if (p.department && c.department === p.department) return 'intra_department';
    return 'intra_agency';
  }
  if (!sameCaseAgency(c, p)) return 'interagency';
  if (p.department && c.department === p.department) {
    if (!p.region || c.region === p.region) return 'intra_department';
  }
  return 'intra_agency';
}

function getCasesBrowsePool() {
  const p = getActivePersona();
  if (caseFilterScope === 'all') return casesRegistry.slice();
  return casesRegistry.filter(c => getCaseJurisdictionScope(c, p) === caseFilterScope);
}

function getCasesRegistryFilterLocks() {
  return { region: false, department: false, agency: false };
}

function applyCaseFilterDefaults(scope = caseFilterScope) {
  const regionSel = document.getElementById('cases-filter-region');
  const deptSel = document.getElementById('cases-filter-department');
  const agencySel = document.getElementById('cases-filter-agency');
  if (!regionSel) return;
  const defaults = getPersonaDefaultFilters();
  if (scope === 'intra_department') {
    if (defaults.region) regionSel.value = defaults.region;
    if (agencySel && defaults.agency) agencySel.value = defaults.agency;
    if (deptSel && defaults.department) deptSel.value = defaults.department;
    return;
  }
  if (scope === 'intra_agency') {
    if (defaults.region) regionSel.value = defaults.region;
    if (agencySel && defaults.agency) agencySel.value = defaults.agency;
    if (deptSel) deptSel.value = CASES_FILTER_ALL;
    return;
  }
  if (scope === 'interagency') {
    if (defaults.region) regionSel.value = defaults.region;
    if (agencySel) agencySel.value = CASES_FILTER_ALL;
    if (deptSel) deptSel.value = CASES_FILTER_ALL;
    return;
  }
  regionSel.value = '';
  if (agencySel) agencySel.value = '';
  if (deptSel) deptSel.value = '';
}

function setCaseFilter(scope) {
  caseFilterScope = scope;
  resetTablePage('cases');
  saveCasesFiltersState();
  applyCaseFilterDefaults(scope);
  renderCasesRegistry();
}

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

function requestIsOutgoingMine(r, p = getActivePersona()) {
  if (p.dashboardMode === 'executor') return requestMatchesPersona(r, p);
  if (p.department && r.department === p.department) return true;
  if (p.department && r.from?.includes(p.department.slice(0, 14))) return true;
  const surname = p.name?.split(/\s+/)[0];
  return !!(surname && r.from?.includes(surname));
}

function getFilteredRequests() {
  const p = getActivePersona();
  let rows = platformRequests.filter(r => requestMatchesPersona(r, p));
  if (requestFilterScope !== 'all') rows = rows.filter(r => r.scope === requestFilterScope);
  if (requestStatusFilter === 'overdue') rows = rows.filter(r => isRequestSlaOverdue(r));
  else if (requestStatusFilter === 'progress') rows = rows.filter(r => ['progress', 'submitted'].includes(r.status));
  else if (requestStatusFilter === 'draft') rows = rows.filter(r => r.status === 'draft');
  else if (requestStatusFilter === 'mine') rows = rows.filter(r => requestIsOutgoingMine(r, p));
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

  document.querySelectorAll('.req-status-chip').forEach(btn => {
    btn.classList.toggle('active', requestStatusFilter === btn.dataset.status);
  });

  if (summary) {
    const pending = getPendingRequestCount(p);
    if (p.dashboardMode === 'executor') {
      summary.textContent = `Очередь · ${p.execAgency || p.group} · ${counts.all} запрос(ов)`;
    } else {
      summary.textContent = `${p.department || p.group} · ${counts.all} запрос(ов)`;
    }
  }

  const notifyHint = document.getElementById('requests-notify-hint');
  const blindHost = document.getElementById('requests-executor-blind');
  if (blindHost) {
    if (isExecutorBlindContour(p)) {
      blindHost.innerHTML = renderExecutorBlindBanner();
      blindHost.classList.remove('hidden');
    } else {
      blindHost.innerHTML = '';
      blindHost.classList.add('hidden');
    }
  }
  if (notifyHint) {
    if (p.dashboardMode === 'executor') {
      notifyHint.textContent = 'Слепой контур: без номера дела и ФИО инициатора. Примите → «Результат» → только объект запроса.';
      notifyHint.classList.remove('hidden');
    } else if (canCreateRequest(p)) {
      notifyHint.textContent = 'После отправки исполнитель получит уведомление в почту и очередь «Запросы». Готовый ответ — кнопка «Ответ».';
      notifyHint.classList.remove('hidden');
    } else {
      notifyHint.classList.add('hidden');
    }
  }

  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="10" class="muted" style="text-align:center;padding:2rem">Нет запросов в выбранной категории</td></tr>`;
    mountTablePagination('requests-pagination', { total: 0, pageSize: TABLE_PAGE_SIZE, key: 'requests' });
    return;
  }

  const meta = paginateList(rows, 'requests', measureTablePageSize(
    document.querySelector('#view-requests .table-scroll-paged')
  ));
  const blind = isExecutorBlindContour(p);
  tbody.innerHTML = meta.slice.map(r => `
    <tr data-request-id="${r.id}" class="${activeRequestHighlightId === r.id ? 'request-row-highlight' : ''}">
      <td>${r.id}</td>
      <td>${renderRequestScopeBadge(r.scope)}</td>
      <td>${escapeHtml(r.type)}</td>
      <td class="req-subject-cell">${blind ? redactRequestForExecutor(r, 'subject') : (r.subject ? escapeHtml(r.subject) : '<span class="muted">—</span>')}</td>
      <td>${escapeHtml(formatRequestTarget(r))}</td>
      <td class="muted">${blind ? redactRequestForExecutor(r, 'from') : escapeHtml(r.from)}</td>
      <td><span class="status ${r.status}">${requestStatusLabels[r.status] || r.status}</span></td>
      <td>${r.sent}</td>
      <td>${renderRequestSlaCell(r)}</td>
      <td class="req-actions-cell">${renderRequestActions(r, p)}</td>
    </tr>`).join('');
  updateRequestsSidebarBadge();
  mountTablePagination('requests-pagination', meta);
}

function setRequestFilter(scope) {
  requestFilterScope = scope;
  resetTablePage('requests');
  saveRequestsFiltersState();
  renderRequests();
}

function setRequestStatusFilter(status) {
  requestStatusFilter = status;
  resetTablePage('requests');
  saveRequestsFiltersState();
  renderRequests();
}

function formatRequestTarget(r) {
  const parts = [r.target];
  if (r.targetDepartment && !parts[0]?.includes(r.targetDepartment)) parts.push(r.targetDepartment);
  let text = parts.filter(Boolean).join(' · ');
  if (r.district) text += ` (${r.district})`;
  return text;
}

function extractDistrictLabel(dept) {
  if (!dept) return '';
  const m = dept.match(/(?:по|СУ по)\s+(.+)$/iu);
  return m ? m[1].trim() : '';
}

function getInteragencyRegion(p = getActivePersona()) {
  const casesRegion = document.getElementById('cases-filter-region')?.value;
  if (casesRegion) return casesRegion;
  const scope = p.caseScope;
  return scope?.region || p.region || '';
}

function getInteragencyDistricts(region) {
  if (!region || region === 'Федеральный') return [];
  const set = new Set(INTERAGENCY_DISTRICTS_BY_REGION[region] || []);
  casesRegistry.filter(c => c.region === region).forEach(c => {
    const d = extractDistrictLabel(c.department);
    if (d) set.add(d);
  });
  Object.values(demoPersonas).filter(x => x.region === region).forEach(x => {
    const d = extractDistrictLabel(x.department);
    if (d) set.add(d);
  });
  return [...set].sort((a, b) => a.localeCompare(b, 'ru'));
}

function getInteragencyExecutorDepartments(agencyId, region, district) {
  const set = new Set();
  const agencyName = agencyRegistry.find(x => x.id === agencyId)?.name || agencyId;

  Object.values(demoPersonas).forEach(p => {
    if (p.dashboardMode !== 'executor') return;
    if (getExecutorAgencyId(p) !== agencyId) return;
    if (region && p.region !== 'Федеральный' && p.region !== region) return;
    if (district && p.region !== 'Федеральный') {
      const pd = extractDistrictLabel(p.department);
      if (pd && pd !== district) return;
    }
    if (p.department) set.add(p.department);
  });

  casesRegistry.forEach(c => {
    if (c.agency !== agencyId) return;
    if (region && c.region !== region) return;
    if (district) {
      const cd = extractDistrictLabel(c.department);
      if (cd && cd !== district) return;
    }
    if (c.department) set.add(c.department);
  });

  const staticPool = INTERAGENCY_DEPTS_BY_AGENCY[agencyId];
  if (staticPool) {
    const regional = staticPool[region];
    if (regional) {
      const districtDepts = district ? regional[district] : null;
      (districtDepts || regional._default || []).forEach(d => set.add(d));
    }
    (staticPool._default || []).forEach(d => set.add(d));
  }

  if (!set.size) set.add(`${agencyName} · центральный аппарат`);
  return [...set].sort((a, b) => a.localeCompare(b, 'ru'));
}

function updateInteragencyDistrictOptions() {
  const districtSel = document.getElementById('req-district');
  if (!districtSel) return;
  const p = getActivePersona();
  const region = getInteragencyRegion(p);
  const hint = document.getElementById('req-interagency-region-hint');
  if (hint) hint.textContent = region && region !== 'Федеральный' ? `Регион: ${region}` : 'Регион: не задан (выберите в реестре дел)';

  const districts = getInteragencyDistricts(region);
  const prev = districtSel.value;
  const personaDistrict = extractDistrictLabel(p.department);

  if (!districts.length) {
    districtSel.innerHTML = '<option value="">— не применяется —</option>';
    districtSel.value = '';
    updateInteragencyDepartmentOptions();
    return;
  }

  districtSel.innerHTML = '<option value="">Выберите район</option>' +
    districts.map(d => `<option value="${escapeHtml(d)}">${escapeHtml(d)}</option>`).join('');
  if (personaDistrict && districts.includes(personaDistrict)) districtSel.value = personaDistrict;
  else if (prev && districts.includes(prev)) districtSel.value = prev;
  updateInteragencyDepartmentOptions();
}

function updateInteragencyDepartmentOptions() {
  const deptSel = document.getElementById('req-target-dept');
  const agencyId = document.getElementById('req-agency')?.value;
  if (!deptSel || !agencyId) return;
  const region = getInteragencyRegion();
  const district = document.getElementById('req-district')?.value || '';
  const depts = getInteragencyExecutorDepartments(agencyId, region, district);
  const prev = deptSel.value;
  deptSel.innerHTML = depts.map(d => `<option value="${escapeHtml(d)}">${escapeHtml(d)}</option>`).join('');
  if (prev && depts.includes(prev)) deptSel.value = prev;
}

function onInteragencyAgencyChange() {
  updateRequestTypes();
  updateInteragencyDepartmentOptions();
}

function createRequestForAgency(agencyId, type) {
  openNewRequestModal('interagency', agencyId, type);
}

function openNewRequestModal(presetScope, presetAgency, presetType, presets = {}) {
  if (!canCreateRequest()) {
    showToast('Создание запросов недоступно для вашей роли (ПОЛ-003).');
    return;
  }
  window._requestHorizonSource = presets.horizonSource || null;
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
  const subjectInput = document.getElementById('req-subject');
  if (subjectInput) subjectInput.value = presets.subject || '';
  const legalInput = document.getElementById('req-legal');
  if (legalInput) legalInput.value = presets.legal || legalInput.value || 'Постановление №412 от 01.06.2028';
  updateRequestScopeFields();
  if (presetType) {
    const typeSel = document.getElementById('req-type');
    if (typeSel && [...typeSel.options].some(o => o.value === presetType)) typeSel.value = presetType;
    updateRequestLawRef();
  } else if (presets.typeLabel) {
    const typeSel = document.getElementById('req-type');
    const opt = [...(typeSel?.options || [])].find(o => o.textContent.includes(presets.typeLabel));
    if (opt) { typeSel.value = opt.value; updateRequestLawRef(); }
  }
  if (!presets.skipTemplateReset) populateRequestArticleTemplates(activeCaseId);
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

  const subjectInput = document.getElementById('req-subject');
  if (subjectInput) {
    subjectInput.placeholder = scope === 'interagency'
      ? 'ФИО, ИНН, ОГРН, счёт, адрес, госномер…'
      : scope === 'intra_agency'
        ? 'ФИО фигуранта, номер дела, объект проверки…'
        : 'ФИО, материал, следственное действие…';
  }

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
    updateInteragencyDistrictOptions();
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
  previewRequestBeforeSubmit();
}

function previewRequestBeforeSubmit() {
  if (!canCreateRequest()) {
    showToast('Создание запросов недоступно для вашей роли (ПОЛ-003).');
    return;
  }
  const scope = document.getElementById('req-scope')?.value || 'interagency';
  const typeSel = document.getElementById('req-type');
  const typeLabel = typeSel?.selectedOptions[0]?.text || '—';
  const legal = document.getElementById('req-legal')?.value.trim();
  const subject = document.getElementById('req-subject')?.value.trim() || '—';
  if (!legal) { showToast('Укажите правовое основание (постановление).'); return; }
  if (!typeSel?.value) { showToast('Выберите тип запроса.'); return; }
  if (scope === 'interagency') {
    if (!document.getElementById('req-district')?.value) { showToast('Выберите район.'); return; }
    if (!document.getElementById('req-target-dept')?.value) { showToast('Выберите отдел исполнителя.'); return; }
  }

  const agencyLabel = scope === 'interagency'
    ? (document.getElementById('req-agency')?.selectedOptions[0]?.text || '—')
    : (getActivePersona().agency || 'ведомство');
  const graphDelta = scope === 'interagency' ? 3 : 1;
  const sla = scope === 'interagency' ? '1–3 раб. дня (СМЭВ)' : scope === 'intra_agency' ? 'до 1 раб. дня' : 'до 4 ч';
  const horizonNote = window._requestHorizonSource
    ? `<li><strong>Источник:</strong> Горизонт · ${escapeHtml(window._requestHorizonSource)}</li>`
    : '';

  const body = document.getElementById('request-simulate-body');
  if (body) {
    body.innerHTML = `
      <p class="muted">Цифровой двойник (IDT-lite): прогноз до отправки · не заменяет согласование</p>
      <ul class="access-explain-facts">
        <li><strong>Запрос:</strong> ${escapeHtml(typeLabel)} → ${escapeHtml(agencyLabel)}</li>
        <li><strong>Объект:</strong> ${escapeHtml(subject)}</li>
        <li><strong>Основание:</strong> ${escapeHtml(legal)}</li>
        ${horizonNote}
        <li><strong>SLA:</strong> ${sla}</li>
        <li><strong>Граф дела:</strong> ожидается +${graphDelta} узла после ответа</li>
        <li><strong>Сроки УПК:</strong> без изменения (демо)</li>
        <li><strong>Журнал:</strong> запись по ПОЛ-003 · цепочка происхождения</li>
      </ul>`;
  }
  document.getElementById('request-simulate-modal')?.classList.remove('hidden');
}

function closeRequestSimulateModal() {
  document.getElementById('request-simulate-modal')?.classList.add('hidden');
}

function confirmRequestAfterSimulation() {
  closeRequestSimulateModal();
  void submitNewRequestAsync();
}

async function submitNewRequestAsync() {
  if (!canCreateRequest()) {
    showToast('Создание запросов недоступно для вашей роли (ПОЛ-003).');
    return;
  }
  const scope = document.getElementById('req-scope')?.value || 'interagency';
  const typeSel = document.getElementById('req-type');
  const typeLabel = typeSel?.selectedOptions[0]?.text || typeSel?.value;
  const legal = document.getElementById('req-legal')?.value.trim();
  const subject = document.getElementById('req-subject')?.value.trim() || '';
  if (!legal) { showToast('Укажите правовое основание (постановление).'); return; }
  if (!typeSel?.value) { showToast('Выберите тип запроса.'); return; }

  const p = getActivePersona();
  requestSeq += 1;
  const id = `Запрос-${requestSeq}`;
  const scopeMeta = REQUEST_SCOPES[scope];
  let target = '';
  let agency = p.agency;
  let district;
  let targetDepartment;
  let region;

  if (scope === 'interagency') {
    const agencyId = document.getElementById('req-agency').value;
    const a = agencyRegistry.find(x => x.id === agencyId);
    target = a ? a.name : agencyId;
    agency = target;
    district = document.getElementById('req-district')?.value.trim() || '';
    targetDepartment = document.getElementById('req-target-dept')?.value.trim() || '';
    if (!district) { showToast('Выберите район для межведомственного запроса.'); return; }
    if (!targetDepartment) { showToast('Выберите отдел исполнителя.'); return; }
    region = getInteragencyRegion(p) || undefined;
  } else if (scope === 'intra_agency') {
    target = document.getElementById('req-target')?.value || 'Подразделение';
  } else {
    target = document.getElementById('req-target')?.value || 'Отдел';
  }

  const executorPersonaId = findExecutorPersonaId({
    target,
    agency: scope === 'interagency' ? target : (p.agency || getPersonaAgencyKey(p)),
    targetDepartment
  });

  const req = {
    id,
    scope,
    type: typeLabel,
    subject: subject || undefined,
    target,
    from: p.department ? `${p.department} · ${p.name.split(' ')[0]}` : `${p.group} · ${p.role}`,
    agency: scope === 'interagency' ? target : (p.agency || getPersonaAgencyKey(p)),
    department: scope === 'intra_department' ? p.department : undefined,
    district: scope === 'interagency' ? district : undefined,
    targetDepartment: scope === 'interagency' ? targetDepartment : undefined,
    region: scope === 'interagency' ? region : undefined,
    requestorPersonaId: p.id,
    executorPersonaId: executorPersonaId || undefined,
    legal,
    status: scope === 'interagency' ? 'submitted' : 'progress',
    sent: 'сегодня',
    sla: scope === 'interagency' ? 'по SLA' : scope === 'intra_agency' ? 'до 1 дня' : 'до 4 ч'
  };

  platformRequests.unshift(req);

  pushCaseProvenance(activeCaseId, {
    type: 'request',
    source: 'Запрос данных',
    detail: `${id} · ${typeLabel} · ${target}${subject ? ' · ' + subject : ''}`,
    policy: 'ПОЛ-003'
  });
  if (window._requestHorizonSource) {
    pushCaseProvenance(activeCaseId, {
      type: 'horizon',
      source: 'Горизонт',
      detail: `Черновик запроса из модуля: ${window._requestHorizonSource}`,
      policy: 'ПОЛ-007'
    });
    window._requestHorizonSource = null;
  }

  closeRequestModal();
  requestFilterScope = scope;
  renderRequests();
  await notifyRequestEvent(req, 'created');
  const subjectNote = subject ? ` · ${subject}` : '';
  const notifyNote = executorPersonaId ? ' · исполнитель уведомлён' : '';
  showToast(`${id}: ${typeLabel} → ${target}${subjectNote} (${scopeMeta.channel})${notifyNote}`);
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

let graphCommsExpanded = { calls: true, sms: false };

function toggleGraphCommsSection(section) {
  if (!['calls', 'sms'].includes(section)) return;
  graphCommsExpanded[section] = !graphCommsExpanded[section];
  refreshGraphCommsPanelOnly();
}

/** @deprecated use toggleGraphCommsSection */
function switchGraphDetailTab(tab) {
  if (!['calls', 'sms'].includes(tab)) return;
  graphCommsExpanded = { calls: tab === 'calls', sms: tab === 'sms' };
  refreshGraphCommsPanelOnly();
}
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
    birthDate: '14.03.1987',
    operator: 'МТС',
    region: 'Краснодарский край',
    regAddress: 'г. Краснодар, ул. Северная, 22, кв. 14',
    registered: '21.08.2019',
    passport: '0319 ****45',
    phone: '+7 (918) 521-21-88',
    caseId: 'ЕПСОК-2028-004521',
    role: 'Фигурант · подозреваемый',
    contactsCount: 47,
    lastContact: '14.06.2028 09:14',
    source: 'ГИАЦ · быстрый запрос',
    note: 'Фигурант ЕПСОК-2028-004521 · повторяющиеся контакты',
    detail: 'SIM зарегистрирована на фигуранта. Зафиксированы повторяющиеся исходящие контакты с номинальной SIM основного объекта. Рекомендуется включение в цепочку доказывания.'
  },
  '9182345512': {
    status: 'unknown',
    statusLabel: 'Не установлен',
    owner: '—',
    operator: 'МегаФон',
    region: 'Краснодарский край',
    regAddress: '—',
    registered: '—',
    phone: '+7 (918) 234-55-12',
    source: 'ГИАЦ · оператор',
    note: 'Абонент не идентифицирован в ИБД · однократный входящий',
    detail: 'Идентификация не завершена. Оператор подтвердил активность SIM без раскрытия персональных данных в рамках быстрого запроса.'
  },
  '9184569033': {
    status: 'nominal',
    statusLabel: 'Номинал',
    owner: 'Сидорова Мария Ивановна',
    birthYear: 1972,
    birthDate: '02.11.1972',
    operator: 'Tele2',
    region: 'Краснодарский край',
    regAddress: 'г. Краснодар, пр. Чекистов, 8',
    registered: '05.01.2024',
    passport: '0317 ****12',
    phone: '+7 (918) 456-90-33',
    source: 'ГИАЦ · запрос оператору',
    note: 'Держатель SIM не совпадает с контрагентом по сделке',
    detail: 'Типичная номинальная регистрация. Держатель не фигурирует в материалах дела.'
  },
  '8432676744': {
    status: 'linked',
    statusLabel: 'Связь установлена',
    owner: 'Ибрагимов Р.К.',
    birthYear: 1991,
    birthDate: '18.07.1991',
    operator: 'Билайн',
    region: 'Респ. Татарстан',
    regAddress: 'г. Казань, ул. Пушкина, 31',
    registered: '14.06.2022',
    phone: '+7 (843) 267-67-44',
    caseId: 'ЕПСОК-2028-002891',
    role: 'Посредник · смежное дело',
    source: 'ГИАЦ · ЕПСОК-2028-002891',
    note: 'Пересечение с делом в Казани · посредник по SIM',
    detail: 'Связь с делом в Казани через общую SIM-цепочку. Межрегиональное совпадение в кластере МВ-2847.'
  },
  '8435121209': {
    status: 'unknown',
    statusLabel: 'Не установлен',
    owner: '—',
    operator: 'МТС',
    region: 'Респ. Татарстан',
    regAddress: '—',
    registered: '—',
    phone: '+7 (843) 512-12-09',
    source: 'ГИАЦ · оператор',
    note: 'Ночной исходящий · идентификация не завершена',
    detail: 'Ночной исходящий вызов. Персональные данные абонента не получены — требуется полноформатный запрос.'
  },
  '9009878901': {
    status: 'linked',
    statusLabel: 'Связь установлена',
    owner: 'Петров Сергей Александрович',
    birthYear: 1985,
    birthDate: '22.05.1985',
    operator: 'Билайн',
    region: 'Респ. Татарстан',
    regAddress: 'г. Казань, ул. Баумана, 8',
    registered: '03.11.2023',
    passport: '9205 ****78',
    phone: '+7 (900) 987-89-01',
    caseId: 'ЕПСОК-2028-002891',
    role: 'Фигурант · смежное дело',
    contactsCount: 12,
    lastContact: '08.06.2028 16:22',
    source: 'ГИАЦ · ЕПСОК-2028-002891',
    note: 'Резервная SIM фигуранта · общий номер в цепочке',
    detail: 'Резервная SIM фигуранта по смежному делу. Пересечение с текущим делом через общие контакты.'
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
    <button type="button" class="link-btn graph-comm-quick-more" onclick="openGraphPeerDetailModal('${phoneKey}')">Подробнее</button>
  </div>`;
}

function getGraphPeerBadgeClass(lookup) {
  if (!lookup) return 'is-pending';
  if (lookup.status === 'suspect' || lookup.status === 'linked') return 'is-match';
  if (lookup.status === 'nominal') return 'is-nominal';
  return 'is-pending';
}

function renderGraphPeerDetailHtml(lookup, phoneKey) {
  const phone = lookup.phone || formatPhoneRu(phoneKey);
  const badgeClass = getGraphPeerBadgeClass(lookup);
  const caseRow = lookup.caseId
    ? `<div class="graph-detail-owner-field graph-detail-owner-field-wide"><dt>Дело</dt><dd><button type="button" class="case-link" onclick="closeGraphPeerDetailModal();openCase('${lookup.caseId}')">${escapeHtml(lookup.caseId)}</button>${lookup.role ? ` · ${escapeHtml(lookup.role)}` : ''}</dd></div>`
    : '';
  const contactsRow = lookup.contactsCount != null
    ? `<div class="graph-detail-owner-field"><dt>Контактов</dt><dd>${lookup.contactsCount} за период</dd></div>`
    : '';
  const lastRow = lookup.lastContact
    ? `<div class="graph-detail-owner-field"><dt>Последний</dt><dd>${escapeHtml(lookup.lastContact)}</dd></div>`
    : '';
  return `
    <div class="graph-peer-detail-summary">
      <span class="graph-detail-owner-badge ${badgeClass}">${escapeHtml(lookup.statusLabel)}</span>
      <span class="graph-peer-detail-phone mono">${escapeHtml(phone)}</span>
    </div>
    <dl class="graph-detail-owner-grid graph-peer-detail-grid">
      <div class="graph-detail-owner-field graph-detail-owner-field-wide"><dt>Абонент</dt><dd>${escapeHtml(lookup.owner)}</dd></div>
      <div class="graph-detail-owner-field"><dt>Дата рожд.</dt><dd>${escapeHtml(lookup.birthDate || lookup.birthYear || '—')}</dd></div>
      <div class="graph-detail-owner-field"><dt>Оператор</dt><dd>${escapeHtml(lookup.operator)}${lookup.registered && lookup.registered !== '—' ? ` · с ${escapeHtml(lookup.registered)}` : ''}</dd></div>
      <div class="graph-detail-owner-field"><dt>Регион</dt><dd>${escapeHtml(lookup.region || '—')}</dd></div>
      <div class="graph-detail-owner-field graph-detail-owner-field-wide"><dt>Адрес рег.</dt><dd>${escapeHtml(lookup.regAddress || '—')}</dd></div>
      ${lookup.passport ? `<div class="graph-detail-owner-field"><dt>Паспорт</dt><dd>${escapeHtml(lookup.passport)}</dd></div>` : ''}
      ${caseRow}
      ${contactsRow}
      ${lastRow}
      <div class="graph-detail-owner-field graph-detail-owner-field-wide"><dt>Источник</dt><dd>${escapeHtml(lookup.source)}</dd></div>
    </dl>
    ${lookup.detail ? `<p class="graph-detail-owner-note">${escapeHtml(lookup.detail)}</p>` : ''}
    <p class="graph-peer-detail-policy muted">ПОЛ-007 · быстрая проверка абонента · демо-контур ГИАЦ</p>`;
}

function openGraphPeerDetailModal(phoneKey) {
  const lookup = graphPeerQuickLookup[phoneKey];
  if (!lookup) {
    showToast('Подробные данные по абоненту недоступны.');
    return;
  }
  const titleEl = document.getElementById('graph-peer-detail-title');
  const bodyEl = document.getElementById('graph-peer-detail-body');
  if (titleEl) titleEl.textContent = lookup.owner && lookup.owner !== '—' ? lookup.owner : 'Абонент';
  if (bodyEl) bodyEl.innerHTML = renderGraphPeerDetailHtml(lookup, phoneKey);
  document.getElementById('graph-peer-detail-modal')?.classList.remove('hidden');
  document.body.classList.add('graph-peer-detail-open');
}

function closeGraphPeerDetailModal() {
  document.getElementById('graph-peer-detail-modal')?.classList.add('hidden');
  document.body.classList.remove('graph-peer-detail-open');
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
  const label = getGraphNodeDisplayLabel(node);
  const sections = [
    { id: 'calls', title: 'Вызовы', count: comm.calls.length, body: renderGraphCallsList(comm.calls, node.id) },
    { id: 'sms', title: 'SMS', count: comm.sms.length, body: renderGraphSmsList(comm.sms, node.id) }
  ];
  return `
    <div class="graph-comms-shell">
      <div class="graph-comms-head">
        <h3 class="graph-comms-title">Коммуникации</h3>
        <span class="graph-comms-sub mono">${escapeHtml(label)}</span>
        <p class="graph-comms-hint muted">Быстрая проверка абонента по каждому контакту · ГИАЦ (ПОЛ-007)</p>
      </div>
      <div class="graph-comms-accordion">
        ${sections.map(s => {
          const open = !!graphCommsExpanded[s.id];
          return `<section class="graph-comms-section${open ? ' is-open' : ''}" data-comms-section="${s.id}">
            <button type="button" class="graph-comms-section-head" onclick="toggleGraphCommsSection('${s.id}')"
              aria-expanded="${open}" aria-controls="graph-comms-body-${s.id}">
              <span class="graph-comms-section-title">${s.title}</span>
              <span class="graph-detail-tab-count">${s.count}</span>
              <span class="graph-comms-section-chevron" aria-hidden="true">${open ? '▾' : '▸'}</span>
            </button>
            <div class="graph-comms-section-body" id="graph-comms-body-${s.id}"${open ? '' : ' hidden'}>${s.body}</div>
          </section>`;
        }).join('')}
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
        <div class="graph-detail-actions">
          <button type="button" class="btn-xs graph-path-add-btn" onclick="addGraphPathPickFromSelection('${node.id}')" title="Добавить в поиск пути">↗ В поиск пути</button>
        </div>
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
  let provenanceHighlightIds = null;
  let pathModifierDown = false;

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
      const onPath = graphPathState.pathEdges?.some(([s, t]) =>
        (s === source && t === target) || (s === target && t === source)
      );
      const lit = onPath || (selectedId && (source === selectedId || target === selectedId));
      ctx.beginPath();
      ctx.moveTo(a.x, a.y);
      ctx.lineTo(b.x, b.y);
      if (onPath) {
        ctx.strokeStyle = 'rgba(245, 158, 11, 0.95)';
        ctx.shadowColor = 'rgba(245, 158, 11, 0.45)';
        ctx.shadowBlur = 8 / transform.k;
      } else if (lit) {
        ctx.strokeStyle = 'rgba(97, 175, 239, 0.75)';
        ctx.shadowColor = 'rgba(97, 175, 239, 0.35)';
        ctx.shadowBlur = 6 / transform.k;
      } else {
        ctx.strokeStyle = 'rgba(255, 255, 255, 0.12)';
        ctx.shadowBlur = 0;
      }
      ctx.lineWidth = (onPath ? 3 : lit ? 2 : 1) / transform.k;
      ctx.stroke();
      ctx.shadowBlur = 0;
    }

    for (const node of simNodes) {
      const isSel = node.id === selectedId;
      const isHov = node.id === hoveredId;
      const isProv = provenanceHighlightIds?.has(node.id);
      const isPathPick = graphPathState.picks.includes(node.id);
      const isOnPath = graphPathState.pathNodeIds?.includes(node.id);
      const isDimmed = (provenanceHighlightIds && !isProv) || (graphPathState.pathNodeIds && !isOnPath && !isPathPick);
      const color = nodeColors[node.type] || '#888';
      const showLabel = isSel || isHov || isProv || transform.k >= 0.55;

      if (isProv) {
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.r + 12, 0, Math.PI * 2);
        ctx.fillStyle = '#f59e0b55';
        ctx.fill();
      }

      if (isOnPath || isPathPick) {
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.r + 11, 0, Math.PI * 2);
        ctx.fillStyle = isOnPath ? '#f59e0b44' : '#a78bfa33';
        ctx.fill();
      }

      if (isSel || isHov) {
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.r + 9, 0, Math.PI * 2);
        ctx.fillStyle = isSel ? color + '55' : color + '33';
        ctx.fill();
      }

      ctx.beginPath();
      ctx.arc(node.x, node.y, node.r, 0, Math.PI * 2);
      if (isDimmed) ctx.globalAlpha = 0.22;
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

      if (showLabel) drawLabel(node, isSel || isHov || isProv);
      ctx.globalAlpha = 1;
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
    if (node?.type === 'phone' && nodeHasCommunications(node)) {
      graphCommsExpanded = { calls: true, sms: false };
    }
    refreshGraphDetailPanel();
    updateGraphPathPanel();
  }

  function selectNodeById(id) {
    const data = graphNodes.find(n => n.id === id);
    if (data) selectNode(data);
  }

  function highlightProvenanceNodes(nodeIds) {
    provenanceHighlightIds = nodeIds?.length ? new Set(nodeIds) : null;
    if (nodeIds?.[0]) {
      cameraFollowId = nodeIds[0];
      focusOnNode(nodeIds[0], { preserveZoom: false });
    }
    alpha = Math.max(alpha, 0.5);
    render();
  }

  function clearProvenanceHighlight() {
    provenanceHighlightIds = null;
    render();
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
    pathModifierDown = !!(e.altKey || e.shiftKey);
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
          if (e.altKey || e.shiftKey || pathModifierDown) toggleGraphPathPick(node.id);
        }
      }
      draggingId = null;
      dragMoved = false;
      pathModifierDown = false;
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
    provenanceHighlightIds = null;
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

  function renderPathState() {
    render();
  }

  return { init, activate, deactivate, resize, relayout, afterDataChange, setCase, resetPositions, selectNode, selectNodeById, highlightProvenanceNodes, clearProvenanceHighlight, renderPathState };
})();

graphView.init();

// --- OSINT Intelligence (demo simulation) ---

const DEMO_CASE_ID = 'ЕПСОК-2028-004521';
let osintScanSeq = 88512;
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

function exportGraphSnapshot() {
  const caseId = activeGraphCaseId;
  if (!caseId) {
    showToast('Сначала выберите дело для графа.');
    return;
  }
  const canvas = document.getElementById('graph-canvas');
  if (!canvas) return;
  try {
    const link = document.createElement('a');
    link.download = sanitizeDownloadFilename(`EPSOK-${caseId.replace(/ЕПСОК-/g, '')}-graph.png`);
    link.href = canvas.toDataURL('image/png');
    link.click();
    pushAuditEntry('Экспорт снимка графа', caseId, 'ПОЛ-004');
    showToast('Снимок графа сохранён (PNG)');
  } catch {
    showToast('Не удалось сохранить снимок графа.');
  }
}

function selectGraphCase(caseId) {
  if (!personaCanBrowseCase(caseId)) {
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
  if (!personaCanBrowseCase(caseId)) {
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
  updateGraphPathPanel();
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
  if (activeCaseId && personaCanBrowseCase(activeCaseId)) return activeCaseId;
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
  },
  {
    id: 'OSINT-88512',
    caseId: 'ЕПСОК-2028-010045',
    targetType: 'VEHICLE_PLATE',
    targetValue: 'К123АВ123',
    profile: 'passive_ru',
    status: 'completed',
    findingCount: 2,
    createdAt: '11.06.2028 11:20',
    legalBasis: 'служебная записка следователя · ориентировка ГИБДД'
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
  syncAccessRequestLink(p);
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
        ${s.status === 'completed' && canLaunchOsintScan() ? `<button type="button" class="btn-xs osint-scan-rerun" onclick="event.stopPropagation();rerunOsintScan('${s.id}')" title="Повторить проверку">↻</button>` : ''}
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

function rerunOsintScan(scanId) {
  const prev = osintScans.find(s => s.id === scanId);
  if (!prev || !canLaunchOsintScan()) return;
  const repeatNum = (prev.repeatCount || 0) + 1;
  document.getElementById('osint-target-type').value = prev.targetType;
  document.getElementById('osint-target-value').value = prev.targetValue;
  document.getElementById('osint-profile').value = prev.profile;
  document.getElementById('osint-legal-basis').value = prev.legalBasis || '';
  const caseSel = document.getElementById('osint-case-select');
  if (caseSel && prev.caseId) caseSel.value = prev.caseId;
  if (prev.options) {
    const cross = document.getElementById('osint-opt-cross');
    const arch = document.getElementById('osint-opt-archive');
    const leak = document.getElementById('osint-opt-leak');
    if (cross) cross.checked = !!prev.options.crossRef;
    if (arch) arch.checked = !!prev.options.archive;
    if (leak) leak.checked = !!prev.options.leakIndex;
  }
  osintScanSeq += 1;
  const newId = `OSINT-${osintScanSeq}`;
  const scan = {
    ...prev,
    id: newId,
    status: 'queued',
    findingCount: 0,
    createdAt: new Date().toLocaleString('ru-RU'),
    repeatCount: repeatNum,
    repeatOf: scanId
  };
  osintScans.unshift(scan);
  selectedOsintScanId = newId;
  renderOsintScans();
  pushAuditEntry('Повтор OSINT', `${newId} · повтор №${repeatNum}`, 'ПОЛ-006');
  showToast(`Повтор проверки ${formatScanId(newId)} · №${repeatNum}`);
  setTimeout(() => { scan.status = 'running'; renderOsintScans(); }, 800);
  const duration = (OSINT_PROFILES[scan.profile]?.depth || 2) * 900 + 1400;
  setTimeout(() => {
    const findings = generateMockFindings(scan.targetType, scan.targetValue, scan.profile, scan.options || {});
    osintFindingsByScan[newId] = findings;
    scan.status = 'completed';
    scan.findingCount = findings.length;
    renderOsintScans();
    renderOsintFindings(newId);
    showToast(`${formatScanId(newId)}: ${findings.length} находок`);
  }, duration);
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
    const linkCaseBtn = !f.importedToGraph && canAccessView('graph') && (!f.requiresReview || f.reviewStatus === 'approved')
      ? `<button type="button" class="btn-xs osint-link-case-btn" onclick="linkOsintFindingToCase('${f.id}','${targetCase || activeCaseId}')">В граф и цепочку</button>`
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
      <td class="osint-finding-actions">${f.importedToGraph ? '<span class="link-badge">в графе</span>' : `${linkCaseBtn}${deepenBtn}`}</td>
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
  const show = loggedIn && isTechAdminPersona();
  el.hidden = !show;
  el.classList.toggle('hidden', !show);
  if (show) {
    const prof = typeof EpsokSecurity?.getSecurityProfile === 'function' ? EpsokSecurity.getSecurityProfile() : null;
    const ctx = prof?.secureContext ? 'TLS/WebCrypto' : 'HTTP-демо';
    el.innerHTML = `<span class="sec-pill sec-pill-gost">ГОСТ TLS 1.3</span><span class="sec-pill">AES-256-GCM</span><span class="sec-pill">HMAC-SHA-256</span><span class="sec-pill">CSP</span><span class="sec-pill">${escapeHtml(ctx)}</span><span class="sec-pill sec-pill-ok">Контур активен</span>`;
  } else {
    el.innerHTML = '';
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

function downloadEvidencePackageManifest(pkgId) {
  const pkg = evidencePackages.find(p => p.id === pkgId);
  if (!pkg) {
    showToast('Пакет доказательств не найден.');
    return;
  }
  if (!personaCanAccessCase(pkg.caseId)) {
    showToast('Нет доступа к пакету доказательств.');
    return;
  }
  const lines = [
    'ЕПСОК · МАНИФЕСТ ПАКЕТА ДОКАЗАТЕЛЬСТВ',
    '====================================',
    `Пакет: ${pkg.id}`,
    `Дело: ${pkg.caseId}`,
    `Проверка: ${formatScanId(pkg.scanId || '—')}`,
    `Создан: ${pkg.createdAt}`,
    `Статус: ${pkg.status}`,
    `SHA-256: ${pkg.hash || '—'}`,
    '',
    'ОБЪЕКТЫ',
    '-------'
  ];
  pkg.findings.forEach((f, i) => {
    lines.push(`${i + 1}. [${osintTypeLabels[f.type] || f.type}] ${f.value}`);
  });
  downloadTextFile(`${pkg.id}-manifest.txt`, appendDemoExportSignatureBlock(lines.join('\n')));
  pushAuditEntry('Манифест пакета доказательств', pkg.id, 'ПОЛ-004');
  showToast(`Манифест сохранён: ${pkg.id}`);
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
        ${canDownload ? `<button type="button" class="btn-sm" onclick="downloadEvidencePackageManifest('${p.id}')">Манифест (TXT)</button><button type="button" class="btn-sm" onclick="downloadEvidencePackagePdf('${p.id}')">Скачать PDF</button>` : ''}
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
  collisionStatus: 'pending',
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
    collision: {
      agency: 'ФСБ России',
      caseToken: 'ХЭШ-9F2A',
      region: 'Краснодарский край',
      signal: 'тот же цифровой отпечаток SIM +7***8901',
      status: 'pending'
    },
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

function renderHorizonCollisionBanner() {
  const profile = getHorizonProfile(activeHorizonCaseId);
  const col = profile.collision;
  if (!col) return '';
  const st = getHorizonCollisionStatus(activeHorizonCaseId);
  if (st === 'coordinated') return '';
  const statusLabel = st === 'requested' ? 'Запрос отправлен' : 'Требуется согласование';
  const viewer = getActivePersona();
  let btn = '';
  if (st === 'requested') {
    if (hasLeadCapabilities(viewer)) {
      btn = `<button type="button" class="btn-sm approve" onclick="approveHorizonCollision('${escapeHtml(activeHorizonCaseId)}')">Согласовано РГ</button>`;
    } else {
      btn = '<span class="link-badge">Ожидание ответа РГ · SLA 4 ч</span>';
    }
  } else {
    btn = '<button type="button" class="btn-sm" onclick="requestHorizonCollisionCoordination()">Запросить согласование РГ</button>';
  }
  const watchBtn = col.caseToken ? renderHorizonWatchTokenBtn(col.caseToken) : '';
  return `<div class="horizon-collision-banner status-${st}">
    <div class="horizon-collision-head"><strong>Параллельное расследование</strong><span class="link-badge">${escapeHtml(statusLabel)}</span>${renderHorizonWatchBadge()}</div>
    <p>${escapeHtml(col.agency)} · токен дела <code>${escapeHtml(col.caseToken)}</code> · ${escapeHtml(col.region)}</p>
    <p class="muted">Сигнал: ${escapeHtml(col.signal)} · без единой базы граждан (ПОЛ-007)</p>
    <div class="horizon-collision-actions">${btn}${watchBtn ? ` ${watchBtn}` : ''}</div>
  </div>`;
}

function loadHorizonCollisionMap() {
  try {
    return JSON.parse(localStorage.getItem(HORIZON_COLLISION_STORAGE) || '{}');
  } catch {
    return {};
  }
}

function getHorizonCollisionStatus(caseId) {
  const stored = loadHorizonCollisionMap()[caseId];
  if (stored) return stored;
  return horizonState.collisionStatus || getHorizonProfile(caseId).collision?.status || 'pending';
}

function setHorizonCollisionStatus(caseId, status) {
  const map = loadHorizonCollisionMap();
  map[caseId] = status;
  localStorage.setItem(HORIZON_COLLISION_STORAGE, JSON.stringify(map));
  if (caseId === activeHorizonCaseId) horizonState.collisionStatus = status;
}

function requestHorizonCollisionCoordination() {
  const profile = getHorizonProfile(activeHorizonCaseId);
  const col = profile.collision;
  if (!col || getHorizonCollisionStatus(activeHorizonCaseId) === 'requested') return;
  setHorizonCollisionStatus(activeHorizonCaseId, 'requested');
  pushCaseProvenance(activeHorizonCaseId, {
    type: 'horizon',
    source: 'Коллизия расследований',
    detail: `Запрос согласования РГ · ${col.agency} · токен ${col.caseToken}`,
    policy: 'ПОЛ-007',
    graphNodeIds: ['ph2', 'c3']
  });
  pushHorizonAlert(`Коллизия: согласование с ${col.agency} · ${col.caseToken}`, 'warning');
  pushAuditEntry('Согласование коллизии', `${col.agency} · ${col.caseToken}`, 'ПОЛ-007');
  renderHorizon();
  refreshHeaderChrome();
  showToast('Запрос согласования рабочих групп направлен');
}

function approveHorizonCollision(caseId) {
  const viewer = getActivePersona();
  if (!hasLeadCapabilities(viewer)) {
    showToast('ПОЛ-007: согласование только руководителем.');
    return;
  }
  if (getHorizonCollisionStatus(caseId) !== 'requested') return;
  const col = getHorizonProfile(caseId).collision;
  setHorizonCollisionStatus(caseId, 'coordinated');
  pushCaseProvenance(caseId, {
    type: 'horizon',
    source: 'Коллизия расследований',
    detail: `Согласовано РГ · ${col?.agency || '—'} · ${col?.caseToken || '—'}`,
    policy: 'ПОЛ-007',
    graphNodeIds: ['ph2', 'c3']
  });
  pushAuditEntry('Коллизия согласована', `${caseId} · ${viewer.name}`, 'ПОЛ-007');
  if (activeHorizonCaseId === caseId) renderHorizon();
  if (document.getElementById('view-staff')?.classList.contains('active')) renderStaff();
  refreshHeaderChrome();
  showToast('Коллизия согласована · запись в цепочке дела');
}

function getPendingHorizonCollisionsForViewer(viewer) {
  if (!hasLeadCapabilities(viewer)) return [];
  const map = loadHorizonCollisionMap();
  return Object.entries(map)
    .filter(([caseId, status]) => status === 'requested' && personaCanAccessCase(caseId))
    .map(([caseId]) => ({ caseId, col: getHorizonProfile(caseId).collision }));
}

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
    collisionStatus: getHorizonCollisionStatus(activeHorizonCaseId),
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
    const col = profile.collision;
    const collisionNote = col && getHorizonCollisionStatus(activeHorizonCaseId) !== 'coordinated'
      ? `<div class="horizon-collision-inline muted">Параллельно: ${escapeHtml(col.agency)} · ${escapeHtml(col.caseToken)} · ${escapeHtml(col.signal)}</div>`
      : '';
    body = `<div class="horizon-alert-card critical serendipity">
      <div class="ha-head"><span class="ha-type">◈ Совпадение</span><span class="ha-time">${horizonState.seRevealRequested ? 'обновлено' : '14.06.2028 03:14'}</span></div>
      <h3>Общий цифровой отпечаток с делом ${escapeHtml(profile.peerPlace)}</h3>
      <p>SIM +7 (***) ***-89-01 · индекс совпадений · ${horizonState.seRevealRequested ? '96' : '94'}% · дело ${escapeHtml(activeHorizonCaseId)}.</p>
      <p class="ha-peer">↔ ${escapeHtml(profile.peerCase)} · ${escapeHtml(profile.peerPlace)}</p>
      ${horizonState.seRevealRequested ? '<p class="link-badge">Запрос раскрытия в очереди · SLA 4 ч</p>' : ''}
      ${collisionNote}
    </div>`;
    actions = `<button type="button" class="btn-sm" onclick="requestPeerReveal('${profile.peerCase}')">${horizonState.seRevealRequested ? '↻ Статус запроса' : 'Запросить раскрытие'}</button>
      ${col && getHorizonCollisionStatus(activeHorizonCaseId) === 'pending' ? `<button type="button" class="btn-sm" onclick="requestHorizonCollisionCoordination()">Согласовать с ${escapeHtml(col.agency)}</button>` : ''}
      <button type="button" class="btn-sm" onclick="openCase('${profile.peerCase}')">Открыть смежное дело</button>`;
  } else if (id === 'GLD') {
    const ghostWatch = (CLUSTER_SHARED_TOKENS[profile.cluster] || []).map(t => renderHorizonWatchTokenBtn(t)).join('');
    body = `<div class="ghost-path">${profile.ghostPath.map((n, i) => `
      <div class="ghost-node ${n.type}"><span class="ghost-dot"></span><span>${escapeHtml(n.label)}</span></div>
      ${i < profile.ghostPath.length - 1 ? '<div class="ghost-arrow">→</div>' : ''}
    `).join('')}</div>
    ${ghostWatch ? `<div class="horizon-watch-ghost-tokens">${ghostWatch}</div>` : ''}
    ${horizonState.ghostRequestSent ? '<p class="link-badge">Межвед. запрос ФНС №88504 создан</p>' : '<p class="muted">Скрытый путь через номинала · уверенность 88%</p>'}`;
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
  const collisionHost = document.getElementById('horizon-collision-host');
  if (collisionHost) collisionHost.innerHTML = renderHorizonCollisionBanner();
  const watchHost = document.getElementById('horizon-watch-host');
  if (watchHost) watchHost.innerHTML = renderHorizonWatchlistPanel();
  const title = document.querySelector('.horizon-title');
  if (title) {
    let slot = document.getElementById('horizon-watch-hero-badge');
    if (!slot) {
      slot = document.createElement('span');
      slot.id = 'horizon-watch-hero-badge';
      slot.className = 'horizon-watch-hero-badge';
      title.appendChild(document.createTextNode(' '));
      title.appendChild(slot);
    }
    slot.innerHTML = renderHorizonWatchBadge();
  }
  renderHorizonCasePicker();
  renderHorizonModulesGrid();
  renderHorizonAlerts();
  renderHorizonModuleDetail(activeHorizonModule);
  const heroActions = document.querySelector('.horizon-hero-actions');
  if (heroActions && !document.getElementById('horizon-cluster-hub-btn')) {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'btn-sm';
    btn.id = 'horizon-cluster-hub-btn';
    btn.textContent = 'Хаб МВ-2847';
    btn.onclick = () => openClusterHub('МВ-2847');
    heroActions.insertBefore(btn, heroActions.querySelector('#horizon-run-btn'));
  }
  refreshHeaderChrome();
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
  const profile = getHorizonProfile(activeHorizonCaseId);
  openNewRequestModal('interagency', 'SK', null, {
    subject: `Раскрытие данных дела ${peerCase} · связь с ${activeHorizonCaseId}`,
    legal: `Постановление · согласование РГ · дело ${activeHorizonCaseId}`,
    horizonSource: `SE: раскрытие ${peerCase} (${profile.peerPlace})`
  });
  horizonState.seRevealRequested = true;
  pushHorizonAlert(`SE: черновик запроса на раскрытие ${peerCase}`, 'info');
  showToast('Открыт черновик межвед. запроса · проверьте поля и симуляцию');
}

function createRequestFromGhost() {
  const profile = getHorizonProfile(activeHorizonCaseId);
  const row = profile.proRows[0];
  const agencyIds = { 'ФНС': 'FNS', 'ФНС России': 'FNS', 'Росфинмониторинг': 'RFM', 'ФССП': 'FSSP', 'МВД (ГИАЦ)': 'MVD' };
  const agencyId = agencyIds[row.agency] || 'FNS';
  openNewRequestModal('interagency', agencyId, null, {
    subject: `Дело ${activeHorizonCaseId} · ${row.name}`,
    legal: `Постановление следователя · дело ${activeHorizonCaseId}`,
    typeLabel: row.name.split(' ')[0],
    horizonSource: `${activeHorizonModule}: ${row.name} (${row.agency})`
  });
  if (activeHorizonModule === 'PRO' || activeHorizonModule === 'GLD') {
    horizonState.proRequestSent = true;
    horizonState.ghostRequestSent = true;
  }
  pushHorizonAlert(`Черновик запроса ${row.agency} · ${row.name}`, 'success');
  showToast('Черновик запроса из Горизонта · симуляция перед отправкой');
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
  { id: 'LOG', name: 'Журнал аудита', icon: '☰', color: '#64748b', summary: 'WORM · неизменяемая запись · только тех. админ', badge: null, kinds: ['tech'] },
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
  if (!canAccessAuditJournal()) return [];
  return [...loadRuntimeAuditLog(), ...adminAuditLogTech];
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

function buildAuditLogSummaryText(source, filtered) {
  const parts = [`Показано ${filtered.length} из ${source.length}`];
  if (auditFilterUser) parts.push(`пользователь: ${formatAuditUserLabel(auditFilterUser)}`);
  if (auditFilterAction) parts.push(`действие: ${auditFilterAction}`);
  if (auditFilterPeriod !== 'all') {
    parts.push(auditFilterPeriod === 'today' ? 'период: сегодня' : 'период: 7 дней');
  }
  if (auditFilterQuery.trim()) parts.push(`поиск: «${auditFilterQuery.trim()}»`);
  return parts.join(' · ');
}

function buildAuditLogTableRowsHtml(source, filtered) {
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
  return {
    meta,
    html: `<div class="table-scroll table-scroll-paged"><table class="data-table audit-log-table"><thead><tr><th>Время</th><th>Пользователь</th><th>Действие</th><th>Объект</th><th>Политика</th></tr></thead><tbody>
        ${tableRows}
      </tbody></table></div>
      ${renderTablePagination(meta)}`
  };
}

function syncAuditLogToolbarState(source) {
  const summaryEl = document.getElementById('audit-filter-summary');
  if (summaryEl) {
    const filtered = filterAuditLogRows(source);
    summaryEl.textContent = buildAuditLogSummaryText(source, filtered);
  }
  document.querySelectorAll('.audit-user-chip').forEach(chip => {
    chip.classList.toggle('active', chip.dataset.user === auditFilterUser);
  });
  const userSel = document.getElementById('audit-filter-user');
  if (userSel && userSel.value !== auditFilterUser) userSel.value = auditFilterUser;
}

function refreshAuditLogView(opts = {}) {
  if (!canAccessAuditJournal()) return;
  tablePageRefresh['admin-audit'] = () => refreshAuditLogView({ preserveToolbar: true });
  const resultsEl = document.getElementById('audit-log-results');
  if (!resultsEl) {
    if (activeAdminModule === 'LOG') renderAdminModuleDetail('LOG');
    return;
  }
  const source = getAdminAuditLogSource();
  const filtered = filterAuditLogRows(source);
  const { html } = buildAuditLogTableRowsHtml(source, filtered);
  resultsEl.innerHTML = html;
  if (opts.preserveToolbar) syncAuditLogToolbarState(source);
}

function onAuditFilterChange() {
  auditFilterUser = document.getElementById('audit-filter-user')?.value || '';
  auditFilterAction = document.getElementById('audit-filter-action')?.value || '';
  auditFilterPeriod = document.getElementById('audit-filter-period')?.value || 'all';
  resetTablePage('admin-audit');
  saveAuditFiltersState();
  refreshAuditLogView({ preserveToolbar: true });
}

function onAuditSearchInput(value) {
  auditFilterQuery = value;
  resetTablePage('admin-audit');
  saveAuditFiltersState();
  refreshAuditLogView({ preserveToolbar: true });
}

function setAuditUserFilter(user) {
  auditFilterUser = auditFilterUser === user ? '' : user;
  resetTablePage('admin-audit');
  saveAuditFiltersState();
  refreshAuditLogView({ preserveToolbar: true });
}

function resetAuditFilters() {
  auditFilterUser = '';
  auditFilterAction = '';
  auditFilterQuery = '';
  auditFilterPeriod = 'all';
  resetTablePage('admin-audit');
  saveAuditFiltersState();
  renderAdminModuleDetail('LOG');
}

function renderAdminAuditLogPanel() {
  if (!canAccessAuditJournal()) {
    return '<p class="muted">ПОЛ-008: журнал аудита доступен только тех. администратору ЦОД.</p>';
  }
  tablePageRefresh['admin-audit'] = () => refreshAuditLogView({ preserveToolbar: true });
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
    return `<button type="button" class="audit-user-chip ${active ? 'active' : ''}" data-user="${escapeHtml(u)}" onclick="setAuditUserFilter('${escapeHtml(u)}')" title="${count} записей">${escapeHtml(formatAuditUserLabel(u))} <span class="audit-chip-count">${count}</span></button>`;
  }).join('');

  const { html: resultsHtml } = buildAuditLogTableRowsHtml(source, filtered);

  return `<p class="muted audit-scope-note">${scopeNote}</p>
    <div class="audit-toolbar" id="audit-log-toolbar">
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
        ${canAccessAuditJournal() ? '<button type="button" class="btn-sm" onclick="exportAuditLogCsv()">Экспорт CSV</button>' : ''}
      </div>
      <div class="audit-user-chips">
        <span class="audit-chips-label">Быстрый выбор пользователя:</span>
        ${userChips}
      </div>
      <p id="audit-filter-summary" class="audit-filter-summary muted">${escapeHtml(buildAuditLogSummaryText(source, filtered))}</p>
    </div>
    <div id="audit-log-results" class="paginated-table-body">
      ${resultsHtml}
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
    body = `${renderAdminIntegrationHealthPanel()}<div class="table-scroll"><table class="data-table"><thead><tr><th>Сервис</th><th>Статус</th><th>Экземпляры</th><th>Время отклика (P99)</th><th>Версия</th></tr></thead><tbody>
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
    if (!canAccessAuditJournal()) {
      body = '<p class="muted">ПОЛ-008: журнал аудита доступен только тех. администратору ЦОД.</p>';
      actions = '';
    } else {
      body = renderAdminAuditLogPanel();
      actions = '<button type="button" class="btn-sm" onclick="exportAuditLogCsv()">Экспорт CSV</button><button type="button" class="btn-sm" onclick="adminExportAudit()">Экспорт в SIEM</button><button type="button" class="btn-sm" onclick="adminRefreshAudit()">↻ Обновить</button>';
    }
  } else if (id === 'INT') {
    body = `<div class="table-scroll"><table class="data-table"><thead><tr><th>Адаптер</th><th>Статус</th><th>Очередь</th><th>Серт. до</th><th></th></tr></thead><tbody>
      ${adminIntegrations.map(i => `<tr><td>${i.agency}</td><td><span class="status ${i.status === 'online' ? 'fulfilled' : 'progress'}">${adminStatusLabel(i.status)}</span></td><td>${i.queue}</td><td>${i.cert}</td><td>${i.status === 'cert_expiring' ? '<button class="btn-xs approve" onclick="adminRotateCert()">Ротация</button>' : ''}</td></tr>`).join('')}
      <tr><td>pravo.gov.ru · НПА</td><td><span class="status fulfilled">${adminStatusLabel('online')}</span></td><td>—</td><td>демо</td><td><button class="btn-xs approve" onclick="adminSyncLegislation()">Синхр.</button></td></tr>
    </tbody></table></div>`;
    actions = '<button type="button" class="btn-sm" onclick="adminSyncLegislation()">↻ Синхронизация нормативной базы</button>';
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
function adminExportAudit() { exportAuditLogCsv(); }
function adminRefreshAudit() { showToast('Журнал аудита: список обновлён.'); refreshAuditLogView({ preserveToolbar: true }); }
function adminScaleWorkers() { showToast('Кластер сбора: 4 → 5 экземпляров (макс. 10).'); }
function adminWhitelistDiff() { showToast('Сбор ОИ: изменение перечня модулей отправлено на согласование.'); }
function adminRebuildBloom() { showToast('«Горизонт»: пересборка индекса совпадений запланирована.'); }
function adminToggleHorizonModule() { showToast('«Горизонт»: переключение модуля — проверка обслуживания.'); }
function adminSchedulePurge() { showToast('Операции: пробная очистка — 15.06.2028 02:00.'); }
function adminMaintenanceWindow() { showToast('Операции: окно обслуживания создано, уведомление пользователей.'); }

// --- Presence / сессии ---

const PRESENCE_ONLINE_IDS = new Set([
  'INV_MVD', 'INV_LEAD_MVD', 'TECH_ADMIN', 'INV_SK', 'ANALYST', 'EXEC_MVD', 'INV_FSB', 'PROSEC', 'BETA_TAKURA'
]);

const PRESENCE_LOGIN_MAP = {
  INV_MVD: 'ivanov.sp',
  INV_LEAD_MVD: 'morozova.ea',
  TECH_ADMIN: 'sidorov.av',
  FUNC_ADMIN: 'kozlov.va',
  INV_SK: 'petrova.ak',
  OPS_MVD: 'sidorov.mv',
  INV_FSB: 'volkov.ia',
  BETA_TAKURA: 'takura.anigatsuki'
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
  const terminated = loadTerminatedSessionIds();
  return Object.keys(demoPersonas)
    .map(id => {
      const pres = getPresence(id);
      if (!pres.online || !pres.sessionId || terminated.has(pres.sessionId)) return null;
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

function loadTerminatedSessionIds() {
  try {
    return new Set(JSON.parse(localStorage.getItem(TERMINATED_SESSIONS_STORAGE) || '[]'));
  } catch {
    return new Set();
  }
}

function terminateStaffSession(sessionId) {
  if (!sessionId) return;
  const viewer = getActivePersona();
  if (!isTechAdminPersona(viewer) && !isBetaRootPersona(viewer)) {
    showToast('ПОЛ-008: завершение сессий — только тех. админ.');
    return;
  }
  const ownSession = getPresence(viewer.id).sessionId;
  if (sessionId === ownSession) {
    showToast('Нельзя завершить собственную сессию из этого интерфейса.');
    return;
  }
  const terminated = loadTerminatedSessionIds();
  terminated.add(sessionId);
  localStorage.setItem(TERMINATED_SESSIONS_STORAGE, JSON.stringify([...terminated]));
  for (const id of Object.keys(demoPersonas)) {
    const pres = getPresence(id);
    if (pres.sessionId === sessionId) {
      pres.online = false;
      pres.lastSeen = 'принудительно завершена';
      pres.sessionId = null;
      pres.ip = null;
      pres.client = null;
      break;
    }
  }
  pushAuditEntry('Завершение сессии', sessionId, 'ПОЛ-008');
  if (document.getElementById('view-staff')?.classList.contains('active')) renderStaff();
  else if (document.getElementById('view-admin')?.classList.contains('active')) renderAdminModuleDetail('SES');
  showToast(`Сессия ${sessionId} завершена`);
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
  MVD: ['Младший лейтенант полиции', 'Лейтенант полиции', 'Старший лейтенант полиции', 'Капитан полиции', 'Майор полиции', 'Подполковник полиции', 'Полковник полиции'],
  SK: ['Младший лейтенант юстиции', 'Лейтенант юстиции', 'Старший лейтенант юстиции', 'Капитан юстиции', 'Майор юстиции', 'Подполковник юстиции', 'Полковник юстиции'],
  FSB: ['Младший лейтенант', 'Лейтенант', 'Старший лейтенант', 'Капитан', 'Майор', 'Подполковник', 'Полковник'],
  FTS: ['Младший специалист', 'Специалист', 'Ведущий специалист', 'Главный специалист', 'Старший инспектор', 'Главный государственный таможенный инспектор'],
  default: ['Младший специалист', 'Специалист', 'Ведущий специалист', 'Главный специалист']
};

const INTERAGENCY_DISTRICTS_BY_REGION = {
  'Краснодарский край': ['Центральный район', 'Прикубанский район', 'Западный округ', 'Карасунский округ', 'Ленинский район', 'Московский район'],
  'Ростовская область': ['Октябрьский район', 'Пролетарский район'],
  'Ставропольский край': ['Ленинский район'],
  'Москва': ['ЮВАО', 'СВАО', 'ЗАО', 'Северный административный округ', 'Ленинский район'],
  'Республика Татарстан': ['Приволжский район']
};

const INTERAGENCY_DEPTS_BY_AGENCY = {
  MVD: {
    _default: ['ГИАЦ · федеральный контур'],
    'Краснодарский край': {
      _default: ['ГИАЦ · Краснодарский край', 'Управление МВД по Краснодарскому краю'],
      'Центральный район': ['ОМВД · Центральный район', 'ГИАЦ · Краснодарский край'],
      'Прикубанский район': ['ОМВД · Прикубанский район', 'ГИАЦ · Краснодарский край'],
      'Западный округ': ['ОМВД · Западный округ', 'ГИАЦ · Краснодарский край']
    },
    'Ростовская область': { _default: ['Управление МВД по Ростовской области', 'ГИАЦ · Ростов-на-Дону'] },
    'Москва': { _default: ['Главное управление МВД по г. Москве', 'ГИАЦ · Москва'] }
  },
  FNS: {
    _default: ['Межрегиональная инспекция ФНС', 'Центральный аппарат ФНС'],
    'Краснодарский край': { _default: ['УФНС по Краснодарскому краю', 'ИФНС №23 по г. Краснодару'] },
    'Москва': { _default: ['УФНС по г. Москве', 'ИФНС №46 по г. Москве'] }
  },
  RFM: { _default: ['Департамент финансового мониторинга', 'Операционный департамент'] },
  FSSP: {
    _default: ['Центральный аппарат ФССП'],
    'Краснодарский край': {
      _default: ['УФССП по Краснодарскому краю'],
      'Центральный район': ['Отдел судебных приставов №1', 'Отдел судебных приставов №3']
    }
  },
  FSIN: { _default: ['УФСИН по региону', 'Центральный аппарат ФСИН'] },
  FTS: { _default: ['Центральное таможенное управление', 'Таможенный пост'] },
  RGV: { _default: ['Управление Росгвардии по региону', 'Лицензионно-разрешительный отдел'] },
  ROSREESTR: { _default: ['Федеральная служба регистрации', 'Управление Росреестра по региону'] },
  CBR: { _default: ['Операционный департамент Банка России'] },
  SK: {
    _default: ['Следственный комитет · центральный аппарат'],
    'Краснодарский край': { _default: ['СУ СК по Краснодарскому краю'] },
    'Москва': { _default: ['СУ по ЮВАО', 'СУ по СВАО', 'СУ по ЗАО'] },
    'Ростовская область': { _default: ['СУ СК по Ростовской области'] }
  }
};

const TRANSFER_REGIONS = ['Краснодарский край', 'Ростовская область', 'Ставропольский край', 'Москва', 'Республика Татарстан'];
const TRANSFER_DEPTS_MVD = ['СО №1 по Прикубанскому району', 'СО №3 по Центральному району', 'СО №7 по Западному округу', 'ОУР №4', 'ОУР №2'];
const TRANSFER_DEPTS_SK = ['СУ по ЮВАО', 'СУ по СВАО', 'СУ по ЗАО', 'СУ по Северному административному округу', 'Следственный отдел по особо важным делам'];
const TRANSFER_DEPTS_FSB = ['Следственный отдел УФСБ', 'Оперативный отдел', 'Отдел контрразведки'];
const TRANSFER_DEPTS_FTS = ['Следственный отдел УТК', 'Таможенный пост «Шереметьево»', 'Таможенный пост «Домодедово»', 'ОТД Таможенного контроля'];
const TRANSFER_AGENCIES = ['МВД России', 'СК России', 'Росгвардия', 'ФТС России'];

function getAgencyDefaultDepts(agency) {
  const key = getAgencyLadderKey(agency);
  if (key === 'MVD') return TRANSFER_DEPTS_MVD;
  if (key === 'SK') return TRANSFER_DEPTS_SK;
  if (key === 'FSB') return TRANSFER_DEPTS_FSB;
  if (key === 'FTS') return TRANSFER_DEPTS_FTS;
  return [];
}

function getTransferDepartmentsForPersona(p = getActivePersona()) {
  const agency = p.agency || getPersonaAgencyKey(p);
  const fromCases = [...new Set(casesRegistry.filter(c => c.agency === agency && c.department).map(c => c.department))];
  const fromPersonas = [...new Set(Object.values(demoPersonas).filter(x => x.agency === agency && x.department).map(x => x.department))];
  const merged = [...new Set([...getAgencyDefaultDepts(agency), ...fromCases, ...fromPersonas])]
    .filter(d => d && d !== p.department);
  const fallback = getAgencyDefaultDepts(agency);
  return merged.length ? merged : fallback;
}

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
  const a = (agency || '').toUpperCase();
  if (a.includes('МВД') || a === 'MVD') return 'MVD';
  if (a.includes('СК') || a === 'SK') return 'SK';
  if (a.includes('ФСБ') || a === 'FSB') return 'FSB';
  if (a.includes('ФТС') || a === 'FTS') return 'FTS';
  return 'default';
}

function userAccountRankOptionsHtml(agency) {
  const ladder = RANK_LADDERS[getAgencyLadderKey(agency)] || RANK_LADDERS.default;
  return ladder.map(r => `<option value="${escapeHtml(r)}">${escapeHtml(r)}</option>`).join('');
}

function updateUserAccountRankOptions(agencySelect) {
  const root = agencySelect?.closest?.('.staff-accounts-form')
    || getUserAccountsFormRoot();
  if (!root) return;
  const agency = agencySelect?.value || root.querySelector('#ua-agency')?.value;
  const rankEl = root.querySelector('#ua-rank');
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
  if (!personaId) return null;
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
  return hasLeadCapabilities(p);
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
  if (!canSubmitHrRequests(p)) {
    if (shouldOfferAccessRequest('hr_self', p)) {
      openAccessRequestModal('hr_self');
    } else {
      showToast('ПОЛ-009: кадровые заявки недоступны для вашей роли.');
    }
    return;
  }
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

function syncProfileTabs(viewer) {
  const canHr = canSubmitHrRequests(viewer);
  document.querySelectorAll('#view-profile .profile-tab[data-tab="requests"]').forEach(btn => {
    btn.classList.toggle('hidden', !canHr);
  });
  if (!canHr && profileTab === 'requests') profileTab = 'card';
}

function renderProfile() {
  const root = document.getElementById('profile-root');
  if (!root) return;
  const viewer = getActivePersona();
  const rec = getPersonnelRecord(viewer.id);
  syncProfileTabs(viewer);
  const ctx = document.getElementById('profile-context');
  if (ctx) {
    const canHr = canSubmitHrRequests(viewer);
    ctx.textContent = profileTab === 'requests' && canHr
      ? 'Статус кадровых заявок · исполнение после согласования'
      : canHr
        ? `${rec.rank} · ${rec.department || viewer.department} · заявки через ПОЛ-009`
        : `${rec.rank} · ${rec.department || viewer.department}`;
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
    <div><dt>Корп. почта</dt><dd class="profile-mail-cell">${corpMailLinkHtml(email)} <button type="button" class="btn-xs profile-copy-email" onclick="copyProfileEmail()" title="Копировать адрес">⎘</button></dd></div>
    <div><dt>ЕСИА</dt><dd><code class="mono-sm">${escapeHtml(pres?.cert || '—')}</code></dd></div>
    ${optional('Дата рождения', rec.birthDate)}
    ${optional('Телефон', rec.phone)}
    ${optional('Образование', rec.education)}
  </dl>`;
}

function renderOwnProfileHrActions(rec) {
  const p = getActivePersona();
  if (!canSubmitHrRequests(p)) {
    if (p.roleType === 'executor') {
      return `<div class="profile-hr-actions profile-hr-actions--muted"><p class="muted profile-hr-hint">Кадровые заявки подаются в системе вашего ведомства · контур исполнителя ЕПСОК.</p></div>`;
    }
    if (isTechAdminPersona(p) || isFuncAdminPersona(p)) return '';
    return `<div class="profile-hr-actions profile-hr-actions--locked">
      <p class="muted profile-hr-hint">Кадровые заявки недоступны для вашей роли.</p>
      <button type="button" class="link-btn" onclick="openAccessRequestModal('hr_self')">Запросить доступ</button>
    </div>`;
  }
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
  if (isBetaRootPersona(viewer)) {
    return ['team', 'hr', 'structures', 'sessions', 'accounts'];
  }
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
  if (isBetaRootPersona(viewer)) {
    const titles = {
      team: 'Состав',
      hr: 'Согласования',
      structures: 'Структуры ведомств',
      sessions: 'Активные сессии',
      accounts: 'Учётные записи'
    };
    return {
      title: titles[tab] || 'Кадры · бета-контур',
      subtitle: 'Полный доступ · тех. и функ. контуры · ПОЛ-009',
      policy: 'ПОЛ-009'
    };
  }
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
        + getPendingAccessRequestsForViewer(viewer).length
        + getPendingHorizonCollisionsForViewer(viewer).length
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
  const tabs = getVisibleStaffTabs(viewer);
  if (!tabs.includes(staffTab)) staffTab = tabs[0] || 'team';

  root.innerHTML = buildStaffPanelHtml(viewer, staffTab, { isTechAdmin, isFuncAdmin, isAdminStaff });

  renderStaffModuleNav(viewer);
  renderStaffHero(viewer, staffTab);

  const layout = document.querySelector('.staff-layout');
  if (layout) layout.classList.toggle('staff-layout-single', tabs.length <= 1);
}

function buildStaffPanelHtml(viewer, tab, ctx = {}) {
  const { isTechAdmin, isFuncAdmin, isAdminStaff } = ctx;
  if (tab === 'accounts' && isAdminStaff) {
    return `<div class="staff-panel-wrap">${renderUserAccountsPanel()}</div>`;
  }
  if (tab === 'structures' && (isTechAdmin || isBetaRootPersona(viewer))) {
    return `<div class="staff-panel-wrap staff-panel-structures">${renderStaffStructuresPanel()}</div>`;
  }
  if (tab === 'sessions' && (isTechAdmin || isBetaRootPersona(viewer))) {
    return `<div class="staff-panel-wrap">${renderStaffSessionsPanel()}</div>`;
  }
  if (tab === 'hr') {
    return `<div class="staff-panel-wrap">${renderStaffHrPanel(viewer)}</div>`;
  }
  return `<div class="staff-panel-wrap">${renderStaffTeamPanel(viewer)}</div>`;
}

function setStaffTab(tab) { staffTab = tab; renderStaff(); }

function renderStaffTeamPanel(viewer) {
  const subs = getSubordinates(viewer.id);
  if (!subs.length) {
    if (isBetaRootPersona(viewer)) {
      return `<div class="panel"><p class="muted">В бета-контуре нет закреплённой линии подчинения. Просмотр всех сотрудников — в разделе <button type="button" class="link-btn" onclick="setStaffTab('structures')">Структуры</button>.</p></div>`;
    }
    if (isAnyAdminPersona(viewer)) {
      return `<div class="panel"><p class="muted">Нет подчинённых в кадровом контуре. Просмотр персонала — в разделе <button type="button" class="link-btn" onclick="setStaffTab('structures')">Структуры</button>.</p></div>`;
    }
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
  if (!rec) {
    return `<div class="panel"><p class="muted">Не удалось открыть личное дело сотрудника.</p></div>`;
  }
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
  const canTerminate = isTechAdminPersona(getActivePersona()) || isBetaRootPersona();
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
        ${canTerminate ? `<td><button type="button" class="btn-xs reject" onclick="terminateStaffSession('${escapeHtml(s.sessionId)}')">Завершить</button></td>` : ''}
      </tr>`).join('')
    : `<tr><td colspan="${canTerminate ? 9 : 8}" class="muted staff-empty-cell">Нет активных сессий</td></tr>`;
  return `<div class="panel staff-sessions-panel">
    <div class="staff-panel-head">
      <h3>Активные подключения</h3>
      <button type="button" class="btn-sm" onclick="adminRefreshSessions(); setStaffTab('sessions')">↻ Обновить</button>
    </div>
    <div class="paginated-table-body">
      <div class="table-scroll table-scroll-paged"><table class="data-table staff-sessions-table"><thead><tr>
        <th>Сессия</th><th>Пользователь</th><th>Ведомство</th><th>Контур</th><th>АРМ / IP</th><th>Регион</th><th>VPN</th><th>Клиент</th>${canTerminate ? '<th></th>' : ''}
      </tr></thead><tbody>
        ${tableRows}
      </tbody></table></div>
      ${renderTablePagination(meta)}
    </div>
  </div>`;
}

function renderStaffHrPanel(viewer) {
  const accessBlock = renderStaffAccessRequestsPanel(viewer);
  const pending = hrRequests.filter(r => r.status === 'submitted' && canManagePersona(viewer.id, r.personaId));
  const horizonPending = getPendingHorizonCollisionsForViewer(viewer);
  const horizonBlock = horizonPending.length
    ? `<div class="panel panel-table" style="margin-bottom:1rem"><h3>Коллизии «Горизонт» (ПОЛ-007)</h3><div class="table-scroll"><table class="data-table"><thead><tr><th>Дело</th><th>Параллельно</th><th>Токен</th><th></th></tr></thead><tbody>
    ${horizonPending.map(({ caseId, col }) => `<tr>
      <td><button type="button" class="link-btn" onclick="selectHorizonCase('${caseId}');showView('horizon')">${escapeHtml(caseId)}</button></td>
      <td>${escapeHtml(col?.agency || '—')}</td>
      <td><code>${escapeHtml(col?.caseToken || '—')}</code></td>
      <td><button class="btn-xs approve" onclick="approveHorizonCollision('${caseId}')">Согласовано</button></td>
    </tr>`).join('')}
    </tbody></table></div></div>`
    : '';
  if (!accessBlock && !pending.length && !horizonBlock) {
    return '<div class="panel"><p class="muted">Нет заявок на согласовании.</p></div>';
  }
  const hrBlock = pending.length
    ? `<div class="panel panel-table"><h3>Кадровые заявки (ПОЛ-009)</h3><div class="table-scroll"><table class="data-table"><thead><tr><th>№</th><th>Сотрудник</th><th>Тип</th><th>Детали</th><th>Основание</th><th></th></tr></thead><tbody>
    ${pending.map(r => { const s = getPersonnelRecord(r.personaId); return `<tr>
      <td>${r.id}</td><td>${escapeHtml(s.name)}</td><td>${HR_REQUEST_TYPES[r.type]?.label}</td>
      <td>${escapeHtml(r.targetRank || r.targetDept || r.targetRegion || r.targetAgency || '—')}</td>
      <td class="muted">${escapeHtml(r.reason)}</td>
      <td><button class="btn-xs approve" onclick="managerApproveHr('${r.id}',true)">Да</button> <button class="btn-xs reject" onclick="managerApproveHr('${r.id}',false)">Нет</button></td>
    </tr>`; }).join('')}
  </tbody></table></div>
  <p class="muted" style="margin-top:0.75rem;font-size:0.8rem">ПОЛ-009: согласование только по линии подчинения. Собственные заявки заблокированы.</p></div>`
    : '';
  return `${horizonBlock}${accessBlock}${hrBlock}`;
}

const USER_ACCOUNT_STATUS = {
  pending: 'На проверке',
  security_ok: 'Проверка пройдена',
  security_fail: 'Отклонено',
  active: 'Учётная запись создана'
};

function getUserAccountsFormRoot() {
  const staffView = document.getElementById('view-staff');
  if (staffView?.classList.contains('active')) {
    const staffForm = document.querySelector('#staff-root .staff-accounts-form');
    if (staffForm) return staffForm;
  }
  const adminView = document.getElementById('view-admin');
  if (adminView?.classList.contains('active')) {
    const adminForm = document.querySelector('#admin-module-detail .staff-accounts-form');
    if (adminForm) return adminForm;
  }
  return document.querySelector('.staff-accounts-form');
}

function readUserAccountFormFields() {
  const root = getUserAccountsFormRoot();
  if (!root) {
    return { name: '', rank: '', role: '', agency: '', manager: '', basis: '' };
  }
  return {
    name: root.querySelector('#ua-name')?.value.trim() || '',
    rank: root.querySelector('#ua-rank')?.value || '',
    role: root.querySelector('#ua-role')?.value.trim() || '',
    agency: root.querySelector('#ua-agency')?.value || '',
    manager: root.querySelector('#ua-manager')?.value.trim() || '',
    basis: root.querySelector('#ua-basis')?.value.trim() || ''
  };
}

function validateUserAccountForm(fields) {
  if (!fields.name) {
    showToast('Укажите ФИО создаваемой учётной записи.');
    return false;
  }
  if (!fields.rank) {
    showToast('Выберите звание.');
    return false;
  }
  if (!fields.role) {
    showToast('Укажите должность.');
    return false;
  }
  if (!fields.basis) {
    showToast('Укажите основание (приказ или штатное расписание).');
    return false;
  }
  if (fields.basis.length < 12) {
    showToast('Основание слишком краткое — укажите номер приказа (не менее 12 символов).');
    return false;
  }
  if (fields.manager === fields.name) {
    showToast('ПОЛ-009: инициатор не может совпадать с создаваемой учётной записью.');
    return false;
  }
  return true;
}

function refreshUserAccountsView() {
  if (document.getElementById('view-staff')?.classList.contains('active')) {
    renderStaff();
  } else if (document.getElementById('view-admin')?.classList.contains('active')) {
    renderAdminModuleDetail('USR');
  }
}

function renderUserAccountsPanel() {
  tablePageRefresh['ua-queue'] = refreshUserAccountsView;
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
      <label class="field"><span>Ведомство</span><select id="ua-agency" onchange="updateUserAccountRankOptions(this)"><option>МВД России</option><option>СК России</option><option>ФСБ России</option></select></label>
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
  const fields = readUserAccountFormFields();
  if (!validateUserAccountForm(fields)) return;
  const { name, rank, role, agency, manager, basis } = fields;
  userAccountSeq += 1;
  const req = { id: `УЗ-${userAccountSeq}`, name, rank, role, agency, manager, basis, status: 'pending', checks: 'Ожидает' };
  userAccountRequests.unshift(req);
  void saveHrState();
  resetTablePage('ua-queue');
  setTimeout(() => runUserAccountSecurityCheck(req.id), 1500);
  refreshUserAccountsView();
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
      void saveHrState();
      refreshUserAccountsView();
      showToast(`${reqId}: учётная запись активирована`);
    }, 2000);
  }
  void saveHrState();
  refreshUserAccountsView();
}

function canEditSuspects() {
  const rt = getActivePersona().roleType;
  return rt === 'inv' || rt === 'inv_lead' || rt === 'ops' || rt === 'beta_root';
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

function renderSuspectsToolbar(total, filtered, opts = {}) {
  const wrap = document.getElementById('suspects-toolbar-wrap');
  if (!wrap) return;
  const inScope = suspectDossiers.filter(s => personaCanAccessCase(s.caseId)).length;
  const filtersOn = suspectFiltersActive();
  const subText = filtersOn
    ? `${filtered} из ${total} · ${inScope} в вашем охвате · остальные — только просмотр`
    : `${total} фигурантов · полный список · ${inScope} в вашем охвате · фильтры ниже необязательны`;
  if (opts.preserveFilters && wrap.querySelector('.suspects-toolbar')) {
    const sub = wrap.querySelector('.suspects-toolbar-sub');
    if (sub) sub.textContent = subText;
    return;
  }
  const regions = getSuspectRegionOptions();
  wrap.innerHTML = `
    <div class="suspects-toolbar panel">
      <div class="suspects-toolbar-head">
        <div>
          <h2 class="suspects-toolbar-title">Дела фигурантов</h2>
          <p class="suspects-toolbar-sub muted">${subText}</p>
        </div>
        <button type="button" class="btn-sm suspects-reset-btn" onclick="resetSuspectFilters()">Сбросить</button>
        <button type="button" class="btn-sm" onclick="exportSuspectsCsv()">CSV</button>
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
  saveSuspectsFiltersState();
  renderSuspects({ preserveFilters: true });
}

function setSuspectFilterRegion(val) {
  suspectFilterRegion = val;
  saveSuspectsFiltersState();
  renderSuspects({ preserveFilters: true });
}

function setSuspectFilterStatus(val) {
  suspectFilterStatus = val;
  saveSuspectsFiltersState();
  renderSuspects({ preserveFilters: true });
}

function resetSuspectFilters() {
  suspectSearchQuery = '';
  suspectFilterRegion = '';
  suspectFilterStatus = '';
  saveSuspectsFiltersState();
  renderSuspects();
}

function renderSuspects(opts = {}) {
  ensureSuspectDossiers();
  const nav = document.getElementById('suspects-nav');
  const detail = document.getElementById('suspects-detail');
  if (!nav || !detail) return;
  const total = suspectDossiers.length;
  const list = getVisibleSuspects();
  renderSuspectsToolbar(total, list.length, opts);

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

  nav.innerHTML = list.map(s => {
    const meta = getSuspectCaseMeta(s.caseId, s);
    const outOfScope = !personaCanAccessCase(s.caseId);
    return `
    <button type="button" class="agencies-nav-item suspects-nav-item ${s.id === activeSuspectId ? 'active' : ''}" onclick="selectSuspect('${s.id}')">
      <span class="suspect-nav-photo">${escapeHtml(suspectAvatar(s))}</span>
      <span class="agencies-nav-text">
        <span class="agencies-nav-name">${escapeHtml(s.lastName)} ${escapeHtml(s.firstName[0])}.${isSuspectWitnessProtected(s.id) ? ' <span class="witness-protect-badge" title="Особая защита · ПОЛ-009">🛡</span>' : ''}</span>
        <span class="agencies-nav-tag">${escapeHtml(s.status)} · ${escapeHtml(meta.region)}</span>
        ${outOfScope ? '<span class="suspects-nav-ro">только просмотр</span>' : ''}
      </span>
    </button>`;
  }).join('');

  detail.innerHTML = renderSuspectForm(list.find(s => s.id === activeSuspectId));
}

function selectSuspect(id) { activeSuspectId = id; renderSuspects(); }

function renderSuspectForm(s) {
  if (!s) return '';
  const editable = canEditSuspectDossier(s);
  const ro = editable ? '' : 'readonly';
  const dis = editable ? '' : 'disabled';
  const meta = getSuspectCaseMeta(s.caseId, s);
  const outOfScope = !personaCanAccessCase(s.caseId);
  const witnessProtected = isSuspectWitnessProtected(s.id);
  return `<div class="panel suspect-form-panel suspect-form-compact">
    <div class="suspect-form-head">
      <div class="suspect-photo-lg">${escapeHtml(suspectAvatar(s))}</div>
      <div class="suspect-form-head-text">
        <h2>${escapeHtml(getSuspectFullName(s))}</h2>
        <span class="badge investigating">${escapeHtml(s.status)}</span>
        ${witnessProtected ? '<span class="witness-protect-badge witness-protect-badge--lg">Особая защита</span>' : ''}
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
      ${editable ? `<label class="field suspect-witness-protect-field">
        <span>Особая защита (ПОЛ-009)</span>
        <button type="button" class="btn-sm witness-protect-toggle${witnessProtected ? ' active' : ''}" onclick="toggleWitnessProtection('${s.id}')">${witnessProtected ? 'Снять режим защиты' : 'Включить «Особая защита»'}</button>
      </label>
      <button type="submit" class="btn-primary btn-sm">Сохранить</button>` : `<p class="muted suspect-ro-hint">${outOfScope ? 'Редактирование недоступно · вы не в составе дела' : 'Только просмотр (надзорный контур)'}</p>`}
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
  const p = getActivePersona();
  if (!canSubmitHrRequests(p)) {
    if (shouldOfferAccessRequest('hr_self', p)) {
      openAccessRequestModal('hr_self');
    } else {
      showToast('ПОЛ-009: кадровые заявки недоступны для вашей роли.');
    }
    return;
  }
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
    const depts = getTransferDepartmentsForPersona();
    fields.innerHTML = `<label class="field"><span>Целевой отдел</span><select id="hr-req-dept">${depts.map(d => `<option>${escapeHtml(d)}</option>`).join('')}</select></label>
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
    if (typeof EpsokSecurity?.initRuntimeGuards === 'function') {
      EpsokSecurity.initRuntimeGuards({ privacyVeil: true });
      EpsokSecurity.bindConfidentialCopyAudit((label) => {
        if (!isAppLoggedIn()) return;
        pushAuditEntry('Копирование из защищённого контура', label, 'ПОЛ-004');
      });
    }
    if (!(await isAuthenticated())) {
      showLoginScreen();
      return;
    }
    hideLoginScreen();
    updateSecurityStrip();
    await loadHrState();
    await loadEvidencePackages();
    loadEvidenceCustody();
    loadVictimNotifications();
    loadCasesRegistryOverrides();
    loadAccessRequests();
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
    initModalDismiss();
    initSidebar();
    initHeaderChrome();
    loadAuditFiltersState();
    initLegislationMonitor();
    const boot = resolveAppBootNavigation();
    showView(boot.view, { skipSave: boot.fromHash, skipHash: boot.fromHash });
    if (boot.view === 'case' && activeCaseId) renderCaseDetail(activeCaseId);
    startSessionGuard();
  } catch (err) {
    console.error(err);
    clearSession();
    showLoginScreen();
    showToast('Сессия устарела. Войдите снова: ivanov.sp / epsok2028');
  }
}

initStructuresNav();
initModalDismiss();
initApp();

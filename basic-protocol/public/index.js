const getElement = (selector) => {
  const element = document.querySelector(selector);

  if (!element) {
    throw new Error(`Missing required element: ${selector}`);
  }

  return element;
};

const documentType = getElement('#documentType');
const proofParameters = getElement('#proofParameters');
const generationDate = getElement('#generationDate');
const generationDateLabel = getElement('#generationDateLabel');
const assertionMonths = getElement('#assertionMonths');
const assertionDuration = getElement('#assertionDuration');
const assertionMonthsUnit = getElement('.input-suffix span');
const form = getElement('.proof-form');
const verifyButton = getElement('#verifyButton');
const buttonLabel = getElement('.button-label');
const spinner = getElement('.spinner');
const verificationStatus = getElement('#verificationStatus');

function updateProofParameters() {
  proofParameters.hidden = documentType.value !== 'military-service';
}

function formatGenerationDate(value) {
  if (!value) {
    return 'the selected date';
  }

  const [year, month, day] = value.split('-').map(Number);
  const date = new Date(Date.UTC(year, month - 1, day));

  return new Intl.DateTimeFormat('en', {
    timeZone: 'UTC',
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  }).format(date);
}

function updateAssertionCopy() {
  const months = Number.parseInt(assertionMonths.value, 10);
  const duration = Number.isInteger(months) && months > 0 ? months : 2;
  const unit = duration === 1 ? 'month' : 'months';

  assertionDuration.textContent = `${duration} ${unit}`;
  assertionMonthsUnit.textContent = unit;
  generationDateLabel.textContent = formatGenerationDate(generationDate.value);
}

async function submitVerification(event) {
  event.preventDefault();
  verifyButton.disabled = true;
  form.setAttribute('aria-busy', 'true');
  buttonLabel.textContent = 'Creating proof…';
  spinner.hidden = false;
  verificationStatus.hidden = true;
  verificationStatus.classList.remove('error');

  try {
    const response = await fetch(form.action, {
      method: 'POST',
      body: new FormData(form),
      headers: { Accept: 'application/json' },
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(result.error ?? 'Verification failed unexpectedly.');
    }

    window.location.assign('/proof');
  } catch (error) {
    verificationStatus.textContent =
      error instanceof Error ? error.message : 'Verification failed unexpectedly.';
    verificationStatus.classList.add('error');
    verificationStatus.hidden = false;
    verifyButton.disabled = false;
    form.removeAttribute('aria-busy');
    buttonLabel.textContent = 'Create proof';
    spinner.hidden = true;
  }
}

documentType.addEventListener('change', updateProofParameters);
generationDate.addEventListener('input', updateAssertionCopy);
assertionMonths.addEventListener('input', updateAssertionCopy);
form.addEventListener('submit', submitVerification);
updateProofParameters();
updateAssertionCopy();

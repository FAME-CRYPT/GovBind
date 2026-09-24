const proofStatus = document.querySelector('#proofStatus');

async function deleteProof(button) {
  const hash = button.dataset.deleteProof;
  if (!hash || !window.confirm('Delete this proof record?')) {
    return;
  }

  button.disabled = true;
  try {
    const response = await fetch('/proof/delete', {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ hash }),
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(result.error ?? 'Could not delete the proof.');
    }

    window.location.reload();
  } catch (error) {
    if (proofStatus) {
      proofStatus.textContent =
        error instanceof Error ? error.message : 'Could not delete the proof.';
      proofStatus.classList.add('error');
      proofStatus.hidden = false;
    }
    button.disabled = false;
  }
}

document.querySelectorAll('[data-delete-proof]').forEach((button) => {
  button.addEventListener('click', () => deleteProof(button));
});

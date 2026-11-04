import { useEffect, useState, type FormEvent } from 'react';
import { Eye, EyeOff, KeyRound, Lock, LockOpen, ShieldCheck, X } from 'lucide-react';
import type { AppStrings } from '../i18n/translations';
import type { Language, PasswordLockMeta } from '../types/archive';
import {
  createPasswordLockMeta,
  validatePasswordInput,
  verifyPasswordLock,
} from '../utils/securityCrypto';

export type FolderLockModalMode = 'set' | 'unlock' | 'change' | 'remove';

interface FolderLockModalProps {
  isOpen: boolean;
  mode: FolderLockModalMode;
  targetName: string;
  lockMeta?: PasswordLockMeta | null;
  language: Language;
  t: AppStrings;
  onClose: () => void;
  onSetNewLock: (newLockMeta: PasswordLockMeta) => Promise<void> | void;
  onUnlocked: () => void;
  onRemoveLock: () => Promise<void> | void;
}

export function FolderLockModal({
  isOpen,
  mode,
  targetName,
  lockMeta,
  language,
  t,
  onClose,
  onSetNewLock,
  onUnlocked,
  onRemoveLock,
}: FolderLockModalProps) {
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPasswords, setShowPasswords] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    if (isOpen) {
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
      setShowPasswords(false);
      setError(null);
      setIsSubmitting(false);
    }
  }, [isOpen, mode, targetName]);

  useEffect(() => {
    if (!isOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !isSubmitting) onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [isOpen, isSubmitting, onClose]);

  if (!isOpen) return null;

  const requiresCurrentPassword = mode === 'unlock' || mode === 'change' || mode === 'remove';
  const requiresNewPassword = mode === 'set' || mode === 'change';

  const title =
    mode === 'set'
      ? t.lockModalSetTitle(targetName)
      : mode === 'unlock'
      ? t.lockModalUnlockTitle(targetName)
      : mode === 'change'
      ? t.lockModalChangeTitle(targetName)
      : t.lockModalRemoveTitle(targetName);

  const description =
    mode === 'set'
      ? t.lockModalSetDesc
      : mode === 'unlock'
      ? t.lockModalUnlockDesc
      : mode === 'change'
      ? t.lockModalChangeDesc
      : t.lockModalRemoveDesc;

  const submitLabel =
    mode === 'set'
      ? t.lockSubmitBtn
      : mode === 'unlock'
      ? t.unlockSubmitBtn
      : mode === 'change'
      ? t.changePasswordSubmitBtn
      : t.removeLockSubmitBtn;

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (isSubmitting) return;
    setError(null);

    if (requiresCurrentPassword && !currentPassword) {
      setError(t.errEmptyPassword);
      return;
    }

    if (requiresNewPassword) {
      const validationErr = validatePasswordInput(newPassword, confirmPassword, language);
      if (validationErr) {
        setError(validationErr);
        return;
      }
    }

    setIsSubmitting(true);
    try {
      if (requiresCurrentPassword) {
        if (!lockMeta) {
          setError(t.errWrongPassword);
          return;
        }
        const ok = await verifyPasswordLock(currentPassword, lockMeta);
        if (!ok) {
          setError(t.errWrongPassword);
          return;
        }
      }

      if (mode === 'unlock') {
        onUnlocked();
        return;
      }

      if (mode === 'remove') {
        await onRemoveLock();
        return;
      }

      const createdMeta = await createPasswordLockMeta(newPassword);
      await onSetNewLock(createdMeta);
    } finally {
      setIsSubmitting(false);
    }
  };

  const inputType = showPasswords ? 'text' : 'password';

  return (
    <div
      className="fixed inset-0 z-[60] flex items-end sm:items-center justify-center bg-black/55 backdrop-blur-xs pt-[max(0.5rem,var(--safe-top))] px-0 pb-0 sm:p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby="folder-lock-modal-title"
      onClick={() => {
        if (!isSubmitting) onClose();
      }}
    >
      <div
        className="w-full sm:max-w-md max-h-[calc(100dvh-0.5rem)] sm:max-h-[85dvh] overflow-y-auto glass-modal rounded-t-[2px] sm:rounded-[2px] px-5 pt-4 pb-[max(0.875rem,calc(var(--safe-bottom)+0.625rem))] sm:p-6"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="pb-3.5 border-b border-stone-900/10 dark:border-white/10">
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-3 min-w-0 flex-1">
              <div className="w-9 h-9 rounded-[2px] glass-control flex items-center justify-center shrink-0 text-stone-800 dark:text-stone-200">
                {mode === 'remove' ? (
                  <LockOpen className="w-4 h-4" aria-hidden="true" />
                ) : mode === 'change' ? (
                  <KeyRound className="w-4 h-4" aria-hidden="true" />
                ) : (
                  <Lock className="w-4 h-4" aria-hidden="true" />
                )}
              </div>
              <h2
                id="folder-lock-modal-title"
                className="text-base font-semibold leading-snug text-stone-900 dark:text-stone-100 break-words min-w-0"
              >
                {title}
              </h2>
            </div>

            <button
              type="button"
              disabled={isSubmitting}
              onClick={onClose}
              aria-label={t.closeMenuAria}
              className="min-h-[40px] min-w-[40px] flex items-center justify-center rounded-[2px] glass-control text-stone-600 hover:text-stone-950 dark:text-stone-300 dark:hover:text-white disabled:opacity-40 shrink-0"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          <p className="mt-2.5 text-xs leading-relaxed text-stone-600 dark:text-stone-400 text-justify">
            {description}
          </p>
        </div>

        <form onSubmit={handleSubmit} className="mt-4 space-y-3.5" noValidate>
          {requiresCurrentPassword && (
            <div>
              <label
                htmlFor="folder-lock-current-password"
                className="block text-xs font-medium text-stone-700 dark:text-stone-300 mb-1.5"
              >
                {mode === 'unlock' ? t.passwordInputLabel : t.currentPasswordLabel}
              </label>
              <div className="relative">
                <input
                  id="folder-lock-current-password"
                  type={inputType}
                  autoFocus
                  autoComplete="current-password"
                  value={currentPassword}
                  onChange={(e) => {
                    setCurrentPassword(e.target.value);
                    if (error) setError(null);
                  }}
                  placeholder={t.passwordPlaceholder}
                  className="w-full min-h-[44px] pl-3.5 pr-11 py-2 rounded-[2px] glass-control text-sm text-stone-900 dark:text-stone-100 placeholder:text-stone-500 dark:placeholder:text-stone-400 focus:outline-none focus:ring-1 focus:ring-stone-900 dark:focus:ring-stone-200"
                />
                <button
                  type="button"
                  onClick={() => setShowPasswords((v) => !v)}
                  aria-label={showPasswords ? t.hidePasswordAria : t.showPasswordAria}
                  className="min-h-[42px] min-w-[42px] absolute right-0.5 top-1/2 -translate-y-1/2 flex items-center justify-center text-stone-500 hover:text-stone-900 dark:text-stone-400 dark:hover:text-stone-100"
                >
                  {showPasswords ? (
                    <EyeOff className="w-4 h-4" aria-hidden="true" />
                  ) : (
                    <Eye className="w-4 h-4" aria-hidden="true" />
                  )}
                </button>
              </div>
            </div>
          )}

          {requiresNewPassword && (
            <>
              <div>
                <label
                  htmlFor="folder-lock-new-password"
                  className="block text-xs font-medium text-stone-700 dark:text-stone-300 mb-1.5"
                >
                  {mode === 'change' ? t.newPasswordLabel : t.passwordInputLabel}
                </label>
                <div className="relative">
                  <input
                    id="folder-lock-new-password"
                    type={inputType}
                    autoFocus={!requiresCurrentPassword}
                    autoComplete="new-password"
                    value={newPassword}
                    onChange={(e) => {
                      setNewPassword(e.target.value);
                      if (error) setError(null);
                    }}
                    placeholder={t.passwordPlaceholder}
                    className="w-full min-h-[44px] pl-3.5 pr-11 py-2 rounded-[2px] glass-control text-sm text-stone-900 dark:text-stone-100 placeholder:text-stone-500 dark:placeholder:text-stone-400 focus:outline-none focus:ring-1 focus:ring-stone-900 dark:focus:ring-stone-200"
                  />
                  {!requiresCurrentPassword && (
                    <button
                      type="button"
                      onClick={() => setShowPasswords((v) => !v)}
                      aria-label={showPasswords ? t.hidePasswordAria : t.showPasswordAria}
                      className="min-h-[42px] min-w-[42px] absolute right-0.5 top-1/2 -translate-y-1/2 flex items-center justify-center text-stone-500 hover:text-stone-900 dark:text-stone-400 dark:hover:text-stone-100"
                    >
                      {showPasswords ? (
                        <EyeOff className="w-4 h-4" aria-hidden="true" />
                      ) : (
                        <Eye className="w-4 h-4" aria-hidden="true" />
                      )}
                    </button>
                  )}
                </div>
              </div>

              <div>
                <label
                  htmlFor="folder-lock-confirm-password"
                  className="block text-xs font-medium text-stone-700 dark:text-stone-300 mb-1.5"
                >
                  {t.confirmPasswordLabel}
                </label>
                <input
                  id="folder-lock-confirm-password"
                  type={inputType}
                  autoComplete="new-password"
                  value={confirmPassword}
                  onChange={(e) => {
                    setConfirmPassword(e.target.value);
                    if (error) setError(null);
                  }}
                  placeholder={t.confirmPasswordPlaceholder}
                  className="w-full min-h-[44px] px-3.5 py-2 rounded-[2px] glass-control text-sm text-stone-900 dark:text-stone-100 placeholder:text-stone-500 dark:placeholder:text-stone-400 focus:outline-none focus:ring-1 focus:ring-stone-900 dark:focus:ring-stone-200"
                />
              </div>
            </>
          )}

          {error && (
            <p
              role="alert"
              className="px-3 py-2 rounded-[2px] bg-red-50/85 dark:bg-red-950/40 border border-red-300 dark:border-red-900/60 text-xs leading-relaxed text-red-700 dark:text-red-300"
            >
              {error}
            </p>
          )}

          <div className="grid grid-cols-2 gap-2.5 pt-2">
            <button
              type="button"
              disabled={isSubmitting}
              onClick={onClose}
              className="min-h-[44px] px-4 py-2 rounded-[2px] glass-control text-xs sm:text-sm font-medium text-stone-800 dark:text-stone-200 disabled:opacity-50 whitespace-nowrap"
            >
              {t.cancelBtn}
            </button>
            <button
              type="submit"
              disabled={isSubmitting}
              className={`min-h-[44px] px-4 py-2 rounded-[2px] text-xs sm:text-sm font-medium disabled:opacity-60 whitespace-nowrap ${
                mode === 'remove'
                  ? 'bg-red-700 text-white dark:bg-red-600 hover:bg-red-800 dark:hover:bg-red-500'
                  : 'bg-stone-900 text-stone-50 dark:bg-stone-100 dark:text-stone-950 hover:bg-stone-800 dark:hover:bg-stone-200'
              }`}
            >
              {isSubmitting ? t.verifyingPasswordBtn : submitLabel}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

interface ExportBackupPasswordModalProps {
  isOpen: boolean;
  language: Language;
  t: AppStrings;
  onClose: () => void;
  /** Invoked synchronously inside the form submit gesture so native/web file pickers retain user activation */
  onConfirmExport: (backupPassword: string | null) => void;
}

export function ExportBackupPasswordModal({
  isOpen,
  language,
  t,
  onClose,
  onConfirmExport,
}: ExportBackupPasswordModalProps) {
  const [exportMode, setExportMode] = useState<'encrypted' | 'plain'>('encrypted');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (isOpen) {
      setExportMode('encrypted');
      setPassword('');
      setConfirmPassword('');
      setShowPassword(false);
      setError(null);
    }
  }, [isOpen]);

  useEffect(() => {
    if (!isOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (exportMode === 'plain') {
      onConfirmExport(null);
      return;
    }

    const validationError = validatePasswordInput(password, confirmPassword, language);
    if (validationError) {
      setError(validationError);
      return;
    }

    onConfirmExport(password);
  };

  const inputType = showPassword ? 'text' : 'password';

  return (
    <div
      className="fixed inset-0 z-[60] flex items-end sm:items-center justify-center bg-black/55 backdrop-blur-xs pt-[max(0.5rem,var(--safe-top))] px-0 pb-0 sm:p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby="export-security-modal-title"
      onClick={onClose}
    >
      <div
        className="w-full sm:max-w-md max-h-[calc(100dvh-0.5rem)] sm:max-h-[85dvh] overflow-y-auto glass-modal rounded-t-[2px] sm:rounded-[2px] px-5 pt-4 pb-[max(0.875rem,calc(var(--safe-bottom)+0.625rem))] sm:p-6"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="pb-3.5 border-b border-stone-900/10 dark:border-white/10">
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-3 min-w-0 flex-1">
              <div className="w-9 h-9 rounded-[2px] glass-control flex items-center justify-center shrink-0 text-stone-800 dark:text-stone-200">
                <ShieldCheck className="w-4 h-4" aria-hidden="true" />
              </div>
              <h2
                id="export-security-modal-title"
                className="text-base font-semibold leading-snug text-stone-900 dark:text-stone-100 break-words min-w-0"
              >
                {t.exportSecurityModalTitle}
              </h2>
            </div>

            <button
              type="button"
              onClick={onClose}
              aria-label={t.closeMenuAria}
              className="min-h-[40px] min-w-[40px] flex items-center justify-center rounded-[2px] glass-control text-stone-600 hover:text-stone-950 dark:text-stone-300 dark:hover:text-white shrink-0"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          <p className="mt-2.5 text-xs leading-relaxed text-stone-600 dark:text-stone-400 text-justify">
            {t.exportSecurityModalDesc}
          </p>
        </div>

        <form onSubmit={handleSubmit} className="mt-4 space-y-4" noValidate>
          {/* Segmented Mode Selector: Encrypted (Default) vs Unencrypted */}
          <div
            role="group"
            aria-label={t.exportSecurityModalTitle}
            className="grid grid-cols-2 gap-1.5 p-1 rounded-[2px] bg-stone-900/[0.06] dark:bg-white/[0.05] border border-stone-900/12 dark:border-white/12"
          >
            <button
              type="button"
              aria-pressed={exportMode === 'encrypted'}
              onClick={() => {
                setExportMode('encrypted');
                setError(null);
              }}
              className={`min-h-[42px] px-2.5 py-2 rounded-[2px] text-xs font-medium inline-flex items-center justify-center gap-1.5 transition-colors ${
                exportMode === 'encrypted'
                  ? 'bg-white/95 dark:bg-white/15 text-stone-900 dark:text-stone-100 border border-stone-900/12 dark:border-white/20 shadow-xs'
                  : 'text-stone-600 dark:text-stone-400 hover:text-stone-900 dark:hover:text-stone-200'
              }`}
            >
              <Lock className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
              <span className="truncate">{t.exportEncryptedModeBtn}</span>
            </button>

            <button
              type="button"
              aria-pressed={exportMode === 'plain'}
              onClick={() => {
                setExportMode('plain');
                setError(null);
              }}
              className={`min-h-[42px] px-2.5 py-2 rounded-[2px] text-xs font-medium inline-flex items-center justify-center gap-1.5 transition-colors ${
                exportMode === 'plain'
                  ? 'bg-white/95 dark:bg-white/15 text-stone-900 dark:text-stone-100 border border-stone-900/12 dark:border-white/20 shadow-xs'
                  : 'text-stone-600 dark:text-stone-400 hover:text-stone-900 dark:hover:text-stone-200'
              }`}
            >
              <LockOpen className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
              <span className="truncate">{t.exportPlainModeBtn}</span>
            </button>
          </div>

          {exportMode === 'encrypted' ? (
            <div className="space-y-3">
              <div>
                <label
                  htmlFor="backup-export-password-input"
                  className="block text-xs font-medium text-stone-700 dark:text-stone-300 mb-1.5"
                >
                  {t.backupPasswordLabel}
                </label>
                <div className="relative">
                  <input
                    id="backup-export-password-input"
                    type={inputType}
                    autoFocus
                    autoComplete="new-password"
                    value={password}
                    onChange={(e) => {
                      setPassword(e.target.value);
                      if (error) setError(null);
                    }}
                    placeholder={t.passwordPlaceholder}
                    className="w-full min-h-[44px] pl-3.5 pr-11 py-2 rounded-[2px] glass-control text-sm text-stone-900 dark:text-stone-100 placeholder:text-stone-500 dark:placeholder:text-stone-400 focus:outline-none focus:ring-1 focus:ring-stone-900 dark:focus:ring-stone-200"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword((v) => !v)}
                    aria-label={showPassword ? t.hidePasswordAria : t.showPasswordAria}
                    className="min-h-[42px] min-w-[42px] absolute right-0.5 top-1/2 -translate-y-1/2 flex items-center justify-center text-stone-500 hover:text-stone-900 dark:text-stone-400 dark:hover:text-stone-100"
                  >
                    {showPassword ? (
                      <EyeOff className="w-4 h-4" aria-hidden="true" />
                    ) : (
                      <Eye className="w-4 h-4" aria-hidden="true" />
                    )}
                  </button>
                </div>
              </div>

              <div>
                <label
                  htmlFor="backup-export-confirm-password-input"
                  className="block text-xs font-medium text-stone-700 dark:text-stone-300 mb-1.5"
                >
                  {t.backupConfirmPasswordLabel}
                </label>
                <input
                  id="backup-export-confirm-password-input"
                  type={inputType}
                  autoComplete="new-password"
                  value={confirmPassword}
                  onChange={(e) => {
                    setConfirmPassword(e.target.value);
                    if (error) setError(null);
                  }}
                  placeholder={t.confirmPasswordPlaceholder}
                  className="w-full min-h-[44px] px-3.5 py-2 rounded-[2px] glass-control text-sm text-stone-900 dark:text-stone-100 placeholder:text-stone-500 dark:placeholder:text-stone-400 focus:outline-none focus:ring-1 focus:ring-stone-900 dark:focus:ring-stone-200"
                />
              </div>
            </div>
          ) : (
            <p className="p-3 rounded-[2px] glass-panel text-xs leading-relaxed text-stone-700 dark:text-stone-300 text-justify">
              {t.exportPlainWarningDesc}
            </p>
          )}

          {error && (
            <p
              role="alert"
              className="px-3 py-2 rounded-[2px] bg-red-50/85 dark:bg-red-950/40 border border-red-300 dark:border-red-900/60 text-xs leading-relaxed text-red-700 dark:text-red-300"
            >
              {error}
            </p>
          )}

          <div className="grid grid-cols-2 gap-2.5 pt-1">
            <button
              type="button"
              onClick={onClose}
              className="min-h-[44px] px-3.5 py-2 rounded-[2px] glass-control text-xs sm:text-sm font-medium text-stone-800 dark:text-stone-200 whitespace-nowrap"
            >
              {t.cancelBtn}
            </button>
            <button
              type="submit"
              className="min-h-[44px] px-3.5 py-2 rounded-[2px] bg-stone-900 text-stone-50 dark:bg-stone-100 dark:text-stone-950 text-xs sm:text-sm font-medium hover:bg-stone-800 dark:hover:bg-stone-200 truncate"
            >
              {t.exportConfirmSubmitBtn}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

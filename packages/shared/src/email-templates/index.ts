// The transactional emails an install sends. STACK's own account emails (sign-in, welcome, the first-customer alert)
// are hosted code under `hosted/email-templates`, built on the page chrome exported from `./transactional.ts`.
export { type EmailChrome, emailChrome, neutralEmailChrome, setEmailChrome } from './chrome.js';
export {
  type TransactionalEmail,
  type NotificationEmailInput,
  type NotificationEmailRenderer,
  setNotificationEmailRenderer,
  memberInviteEmail,
  emailChangeConfirmEmail,
  emailChangeNoticeEmail,
  emailChangeCompletedEmail,
  notificationEmail,
  notificationVerificationEmail,
} from './transactional.js';

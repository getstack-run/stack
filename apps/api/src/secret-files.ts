import { loadSecretFiles } from '@stack/shared';

// Settings given as NAME_FILE (a mounted secret) are read into NAME before anything else reads the environment.
loadSecretFiles();

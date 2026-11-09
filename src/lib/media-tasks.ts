/** The kinds of model the media runner serves: Diffusers pipelines and text-to-speech. A model's
 * status names its task; a media task gets the Generate view, the job API examples and the
 * media usage tiles where a text model gets chat. */
export const MEDIA_TASKS = ["text-to-image", "image-to-image", "text-to-video", "image-to-video", "text-to-audio", "text-to-speech"] as const
export type MediaTask = (typeof MEDIA_TASKS)[number]
export const isMediaTask = (task: string | undefined): task is MediaTask => MEDIA_TASKS.includes(task as MediaTask)

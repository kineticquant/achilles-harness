import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import ImagePreview from './ImagePreview';
import MarkdownContent from './MarkdownContent';
import {
  getTextAndImageContent,
  imageDataFromMessage,
  type ImageData,
  type Message,
} from '../types/message';
import MessageCopyLink from './MessageCopyLink';
import { formatMessageTimestamp } from '../utils/timeUtils';
import Close from './icons/Close';
import Edit from './icons/Edit';
import { RefreshCw, Trash2 } from 'lucide-react';
import { Button } from './ui/button';
import { ConfirmationModal } from './ui/ConfirmationModal';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from './ui/collapsible';
import Expand from './ui/Expand';
import { defineMessages, useIntl } from '../i18n';
import { cn } from '../utils';
import {
  composeFindingChatPayload,
  findingContextTitle,
  splitFindingChatPayload,
} from './findings/findingChat';

const i18n = defineMessages({
  editPlaceholder: {
    id: 'userMessage.editPlaceholder',
    defaultMessage: 'Edit your message...',
  },
  editAriaLabel: {
    id: 'userMessage.editAriaLabel',
    defaultMessage: 'Edit message content',
  },
  emptyError: {
    id: 'userMessage.emptyError',
    defaultMessage: 'Message cannot be empty',
  },
  findingContext: {
    id: 'userMessage.findingContext',
    defaultMessage: 'Finding context',
  },
  findingContextWithTitle: {
    id: 'userMessage.findingContextWithTitle',
    defaultMessage: 'Finding · {title}',
  },
  editInPlaceDescription: {
    id: 'userMessage.editInPlaceDescription',
    defaultMessage:
      '<b>Edit in Place</b> updates this session • <b>Fork Session</b> creates a new session',
  },
  cancel: {
    id: 'userMessage.cancel',
    defaultMessage: 'Cancel',
  },
  cancelAriaLabel: {
    id: 'userMessage.cancelAriaLabel',
    defaultMessage: 'Cancel editing',
  },
  editInPlace: {
    id: 'userMessage.editInPlace',
    defaultMessage: 'Edit in Place',
  },
  editInPlaceAriaLabel: {
    id: 'userMessage.editInPlaceAriaLabel',
    defaultMessage: 'Edit message in place',
  },
  editInPlaceTitle: {
    id: 'userMessage.editInPlaceTitle',
    defaultMessage: 'Update the message in this session',
  },
  forkSession: {
    id: 'userMessage.forkSession',
    defaultMessage: 'Fork Session',
  },
  forkSessionAriaLabel: {
    id: 'userMessage.forkSessionAriaLabel',
    defaultMessage: 'Fork session with edited message',
  },
  forkSessionTitle: {
    id: 'userMessage.forkSessionTitle',
    defaultMessage: 'Create a new session with the edited message',
  },
  editButton: {
    id: 'userMessage.editButton',
    defaultMessage: 'Edit',
  },
  editMessageAriaLabel: {
    id: 'userMessage.editMessageAriaLabel',
    defaultMessage: 'Edit message: {preview}',
  },
  editMessageTitle: {
    id: 'userMessage.editMessageTitle',
    defaultMessage: 'Edit message',
  },
  removeImageFromEdit: {
    id: 'userMessage.removeImageFromEdit',
    defaultMessage: 'Remove image from message',
  },
  editImagesHeading: {
    id: 'userMessage.editImagesHeading',
    defaultMessage: 'Attached images:',
  },
  resendButton: {
    id: 'userMessage.resendButton',
    defaultMessage: 'Resend',
  },
  resendAriaLabel: {
    id: 'userMessage.resendAriaLabel',
    defaultMessage: 'Resend message: {preview}',
  },
  resendTitle: {
    id: 'userMessage.resendTitle',
    defaultMessage: 'Send this message again',
  },
  deleteButton: {
    id: 'userMessage.deleteButton',
    defaultMessage: 'Delete',
  },
  deleteAriaLabel: {
    id: 'userMessage.deleteAriaLabel',
    defaultMessage: 'Delete message: {preview}',
  },
  deleteTitle: {
    id: 'userMessage.deleteTitle',
    defaultMessage: 'Delete this message',
  },
  deleteConfirmTitle: {
    id: 'userMessage.deleteConfirmTitle',
    defaultMessage: 'Delete message',
  },
  deleteConfirmMessage: {
    id: 'userMessage.deleteConfirmMessage',
    defaultMessage: 'This will remove this message and everything after it from the session.',
  },
  deleteConfirmAction: {
    id: 'userMessage.deleteConfirmAction',
    defaultMessage: 'Delete',
  },
  deleteCancel: {
    id: 'userMessage.deleteCancel',
    defaultMessage: 'Cancel',
  },
});

interface UserMessageProps {
  message: Message;
  onMessageUpdate?: (
    messageId: string,
    newContent: string,
    editType: 'fork' | 'edit',
    retainedImages: ImageData[]
  ) => void;
  onMessageDelete?: (messageId: string) => void | Promise<void>;
}

const actionButtonClass =
  'flex items-center gap-1 text-xs text-text-secondary hover:cursor-pointer hover:text-text-primary transition-all duration-200 opacity-0 group-hover:opacity-100 -translate-y-4 group-hover:translate-y-0 focus:outline-none focus:ring-2 focus:ring-blue-400 focus:ring-opacity-50 focus-visible:opacity-100 focus-visible:translate-y-0 rounded';

export default function UserMessage({
  message,
  onMessageUpdate,
  onMessageDelete,
}: UserMessageProps) {
  const intl = useIntl();
  const contentRef = useRef<HTMLDivElement | null>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const [isEditing, setIsEditing] = useState(false);
  const [editContent, setEditContent] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);

  const { textContent, imagePaths } = getTextAndImageContent(message);
  const timestamp = formatMessageTimestamp(message.created);
  const attached = useMemo(() => splitFindingChatPayload(textContent), [textContent]);
  const displayText = attached?.question ?? textContent;
  const contextLabel = useMemo(() => {
    if (!attached) return '';
    const title = findingContextTitle(attached.context);
    return title
      ? intl.formatMessage(i18n.findingContextWithTitle, { title })
      : intl.formatMessage(i18n.findingContext);
  }, [attached, intl]);

  const messageImages: ImageData[] = imageDataFromMessage(message);

  const [removedImageIndices, setRemovedImageIndices] = useState<Set<number>>(new Set());
  const [contextOpen, setContextOpen] = useState(false);

  useEffect(() => {
    if (!isEditing) {
      setEditContent(displayText);
    }
  }, [message.content, displayText, message.id, isEditing]);

  const initializeEditMode = useCallback(() => {
    setEditContent(displayText);
    setError(null);
    setRemovedImageIndices(new Set());
    window.electron.logInfo(`Entering edit mode with content: ${displayText}`);
  }, [displayText]);

  const handleRemoveImage = useCallback((index: number) => {
    setRemovedImageIndices((prev) => {
      const next = new Set(prev);
      next.add(index);
      return next;
    });
  }, []);

  const handleEditClick = useCallback(() => {
    const newEditingState = !isEditing;
    setIsEditing(newEditingState);

    if (newEditingState) {
      initializeEditMode();
      window.electron.logInfo(`Edit interface shown for message: ${message.id}`);

      setTimeout(() => {
        if (textareaRef.current) {
          textareaRef.current.focus();
          textareaRef.current.setSelectionRange(
            textareaRef.current.value.length,
            textareaRef.current.value.length
          );
        }
      }, 50);
    }

    window.electron.logInfo(`Edit state toggled: ${newEditingState} for message: ${message.id}`);
  }, [isEditing, initializeEditMode, message.id]);

  const handleContentChange = useCallback((e: React.ChangeEvent<HTMLTextAreaElement>) => {
    const newContent = e.target.value;
    setEditContent(newContent);
    setError(null);
    window.electron.logInfo(`Content changed: ${newContent}`);
  }, []);

  const handleSave = useCallback(
    (editType: 'fork' | 'edit') => {
      const retainedImages = messageImages.filter((_, index) => !removedImageIndices.has(index));

      if (editContent.trim().length === 0 && retainedImages.length === 0) {
        setError(intl.formatMessage(i18n.emptyError));
        return;
      }

      setIsEditing(false);

      if (
        editType === 'edit' &&
        editContent.trim() === displayText.trim() &&
        retainedImages.length === messageImages.length
      ) {
        return;
      }

      const nextContent = attached
        ? composeFindingChatPayload(attached.context, editContent)
        : editContent;

      if (onMessageUpdate && message.id) {
        onMessageUpdate(message.id, nextContent, editType, retainedImages);
      }
    },
    [
      attached,
      displayText,
      editContent,
      onMessageUpdate,
      message.id,
      intl,
      messageImages,
      removedImageIndices,
    ]
  );

  const handleCancel = useCallback(() => {
    window.electron.logInfo('Cancel clicked - reverting to original content');
    setIsEditing(false);
    setEditContent(displayText);
    setError(null);
  }, [displayText]);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      window.electron.logInfo(
        `Key pressed: ${e.key}, metaKey: ${e.metaKey}, ctrlKey: ${e.ctrlKey}`
      );

      if (e.key === 'Escape') {
        e.preventDefault();
        handleCancel();
      } else if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        window.electron.logInfo('Cmd+Enter detected, calling handleSave');
        handleSave('fork');
      }
    },
    [handleCancel, handleSave]
  );

  const handleResend = useCallback(() => {
    if (!onMessageUpdate || !message.id) return;
    if (!textContent.trim() && messageImages.length === 0) return;
    onMessageUpdate(message.id, textContent, 'edit', messageImages);
  }, [onMessageUpdate, message.id, textContent, messageImages]);

  const messagePreview = `${displayText.substring(0, 50)}${displayText.length > 50 ? '...' : ''}`;

  const handleDeleteClick = useCallback(() => {
    if (!onMessageDelete || !message.id) return;
    setConfirmDelete(true);
  }, [onMessageDelete, message.id]);

  const handleConfirmDelete = useCallback(async () => {
    if (!onMessageDelete || !message.id) return;
    setIsDeleting(true);
    try {
      await onMessageDelete(message.id);
      setConfirmDelete(false);
    } finally {
      setIsDeleting(false);
    }
  }, [onMessageDelete, message.id]);

  useEffect(() => {
    if (textareaRef.current && isEditing) {
      textareaRef.current.style.height = 'auto';
      textareaRef.current.style.height = `${Math.min(textareaRef.current.scrollHeight, 200)}px`;
    }
  }, [editContent, isEditing]);

  return (
    <div className="w-full mt-[16px] opacity-0 animate-[appear_150ms_ease-in_forwards]">
      <div className="flex flex-col group">
        {isEditing ? (
          <div className="w-full max-w-4xl mx-auto text-text-primary rounded-xl border border-border-primary shadow-lg py-4 px-4 my-2 transition-all duration-200 ease-in-out">
            <textarea
              ref={textareaRef}
              value={editContent}
              onChange={handleContentChange}
              onKeyDown={handleKeyDown}
              className="w-full resize-none bg-transparent text-text-primary placeholder:text-text-secondary border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-400 focus:border-blue-400 transition-all duration-200 text-base leading-relaxed"
              style={{
                minHeight: '120px',
                maxHeight: '300px',
                padding: '16px',
                fontFamily: 'inherit',
                lineHeight: '1.6',
                wordBreak: 'break-word',
                overflowWrap: 'break-word',
              }}
              placeholder={intl.formatMessage(i18n.editPlaceholder)}
              aria-label={intl.formatMessage(i18n.editAriaLabel)}
              aria-describedby={error ? `error-${message.id}` : undefined}
            />
            {messageImages.length > 0 && (
              <div className="mt-3">
                <p className="text-xs text-text-secondary mb-2">
                  {intl.formatMessage(i18n.editImagesHeading)}
                </p>
                <div className="flex flex-wrap gap-2">
                  {messageImages.map((img, index) => {
                    if (removedImageIndices.has(index)) return null;
                    const dataUrl = `data:${img.mimeType};base64,${img.data}`;
                    return (
                      <div key={index} className="relative group/image">
                        <ImagePreview src={dataUrl} />
                        <button
                          onClick={() => handleRemoveImage(index)}
                          className="absolute -top-1.5 -right-1.5 bg-text-primary text-background-primary rounded-full p-0.5 transition-opacity hover:cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400"
                          aria-label={intl.formatMessage(i18n.removeImageFromEdit)}
                        >
                          <Close className="h-3 w-3" />
                        </button>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
            {error && (
              <div
                id={`error-${message.id}`}
                className="text-red-400 text-xs mt-2 mb-2"
                role="alert"
                aria-live="polite"
              >
                {error}
              </div>
            )}
            <div className="flex justify-between items-center mt-4">
              <div className="text-xs text-text-secondary">
                {intl.formatMessage(i18n.editInPlaceDescription, {
                  b: (chunks: React.ReactNode) => <span className="font-semibold">{chunks}</span>,
                })}
              </div>
              <div className="flex gap-3">
                <Button
                  onClick={handleCancel}
                  variant="ghost"
                  aria-label={intl.formatMessage(i18n.cancelAriaLabel)}
                >
                  {intl.formatMessage(i18n.cancel)}
                </Button>
                <Button
                  onClick={() => handleSave('edit')}
                  variant="secondary"
                  aria-label={intl.formatMessage(i18n.editInPlaceAriaLabel)}
                  title={intl.formatMessage(i18n.editInPlaceTitle)}
                >
                  {intl.formatMessage(i18n.editInPlace)}
                </Button>
                <Button
                  onClick={() => handleSave('fork')}
                  aria-label={intl.formatMessage(i18n.forkSessionAriaLabel)}
                  title={intl.formatMessage(i18n.forkSessionTitle)}
                >
                  {intl.formatMessage(i18n.forkSession)}
                </Button>
              </div>
            </div>
          </div>
        ) : (
          <div className="message flex justify-end w-full">
            <div className="flex-col max-w-[85%] w-fit">
              <div className="flex flex-col group items-end">
                {attached && (
                  <Collapsible
                    open={contextOpen}
                    onOpenChange={setContextOpen}
                    className="mb-1.5 w-full"
                  >
                    <div className="flex justify-end">
                      <CollapsibleTrigger
                        className="inline-flex max-w-full items-center gap-1 rounded-md border border-border-primary bg-background-primary px-2 py-0.5 text-[11px] leading-4 text-text-secondary hover:text-text-primary transition-colors cursor-pointer"
                        aria-label={contextLabel}
                      >
                        <Expand size={3} isExpanded={contextOpen} />
                        <span className="truncate">{contextLabel}</span>
                      </CollapsibleTrigger>
                    </div>
                    <CollapsibleContent>
                      <pre className="mt-1 max-w-full overflow-x-auto whitespace-pre-wrap break-all rounded-md border border-border-primary bg-background-primary px-2 py-1.5 text-left font-mono text-[11px] leading-5 text-text-secondary">
                        {attached.context}
                      </pre>
                    </CollapsibleContent>
                  </Collapsible>
                )}
                {displayText.trim() && (
                  <div className="user-message-bubble flex bg-text-primary text-background-primary rounded-xl py-2.5 px-4">
                    <div ref={contentRef}>
                      <MarkdownContent
                        content={displayText}
                        className="!text-inherit prose-a:!text-inherit prose-headings:!text-inherit prose-strong:!text-inherit prose-em:!text-inherit prose-li:!text-inherit prose-p:!text-inherit user-message"
                      />
                    </div>
                  </div>
                )}

                {imagePaths.length > 0 && (
                  <div className="flex flex-wrap gap-2 mt-2">
                    {imagePaths.map((imagePath, index) => (
                      <ImagePreview key={index} src={imagePath} />
                    ))}
                  </div>
                )}

                <div className="relative h-[22px] flex justify-end text-right">
                  <div className="absolute w-40 font-mono right-0 text-xs text-text-secondary pt-1 transition-all duration-200 group-hover:-translate-y-4 group-hover:opacity-0">
                    {timestamp}
                  </div>
                  <div className="absolute right-0 pt-1 flex items-center gap-2 whitespace-nowrap">
                    <button
                      type="button"
                      onClick={handleEditClick}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' || e.key === ' ') {
                          e.preventDefault();
                          handleEditClick();
                        }
                      }}
                      className={actionButtonClass}
                      aria-label={intl.formatMessage(i18n.editMessageAriaLabel, {
                        preview: messagePreview,
                      })}
                      aria-expanded={isEditing}
                      title={intl.formatMessage(i18n.editMessageTitle)}
                    >
                      <Edit className="h-3 w-3" />
                      <span>{intl.formatMessage(i18n.editButton)}</span>
                    </button>
                    <MessageCopyLink text={displayText} contentRef={contentRef} />
                    {onMessageUpdate && message.id && (
                      <button
                        type="button"
                        onClick={handleResend}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter' || e.key === ' ') {
                            e.preventDefault();
                            handleResend();
                          }
                        }}
                        className={actionButtonClass}
                        aria-label={intl.formatMessage(i18n.resendAriaLabel, {
                          preview: messagePreview,
                        })}
                        title={intl.formatMessage(i18n.resendTitle)}
                      >
                        <RefreshCw className="h-3 w-3" />
                        <span>{intl.formatMessage(i18n.resendButton)}</span>
                      </button>
                    )}
                    {onMessageDelete && message.id && (
                      <button
                        type="button"
                        onClick={handleDeleteClick}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter' || e.key === ' ') {
                            e.preventDefault();
                            handleDeleteClick();
                          }
                        }}
                        className={cn(actionButtonClass, 'hover:text-text-danger')}
                        aria-label={intl.formatMessage(i18n.deleteAriaLabel, {
                          preview: messagePreview,
                        })}
                        aria-haspopup="dialog"
                        title={intl.formatMessage(i18n.deleteTitle)}
                      >
                        <Trash2 className="h-3 w-3" />
                        <span>{intl.formatMessage(i18n.deleteButton)}</span>
                      </button>
                    )}
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
      <ConfirmationModal
        isOpen={confirmDelete}
        title={intl.formatMessage(i18n.deleteConfirmTitle)}
        message={intl.formatMessage(i18n.deleteConfirmMessage)}
        confirmLabel={intl.formatMessage(i18n.deleteConfirmAction)}
        cancelLabel={intl.formatMessage(i18n.deleteCancel)}
        confirmVariant="destructive"
        isSubmitting={isDeleting}
        onConfirm={() => {
          void handleConfirmDelete();
        }}
        onCancel={() => {
          if (!isDeleting) setConfirmDelete(false);
        }}
      />
    </div>
  );
}

import React, { useEffect, useRef } from 'react';
import clsx from 'clsx';
import './Table.css';

interface Column<T> {
  key: string;
  header: string;
  accessor: (item: T) => React.ReactNode;
  width?: string;
  align?: 'left' | 'center' | 'right';
  sortable?: boolean;
}

interface TableProps<T> {
  columns: Column<T>[];
  data: T[];
  keyExtractor: (item: T) => string;
  onRowClick?: (item: T) => void;
  selectedRows?: Set<string>;
  onRowSelect?: (id: string, selected: boolean) => void;
  onSelectAll?: (selected: boolean) => void;
  loading?: boolean;
  emptyMessage?: string;
  className?: string;
  rowClassName?: (item: T, index: number) => string | undefined;
}

export default function Table<T>({
  columns,
  data,
  keyExtractor,
  onRowClick,
  selectedRows,
  onRowSelect,
  onSelectAll,
  loading = false,
  emptyMessage = 'No data available',
  className,
  rowClassName,
}: TableProps<T>) {
  const selectedSet = selectedRows ?? new Set<string>();
  const hasSelection = selectedRows !== undefined && onRowSelect !== undefined;
  const allSelected = hasSelection && data.length > 0 && data.every(item => selectedSet.has(keyExtractor(item)));
  const someSelected = hasSelection && data.some(item => selectedSet.has(keyExtractor(item)));
  const selectAllRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (selectAllRef.current) {
      selectAllRef.current.indeterminate = Boolean(hasSelection && someSelected && !allSelected);
    }
  }, [hasSelection, someSelected, allSelected]);

  return (
    <div className={clsx('table-container', className)}>
      <table className="table">
        <thead className="table-head">
          <tr>
            {hasSelection && (
              <th className="table-cell table-cell-checkbox">
                <input
                  type="checkbox"
                  className="checkbox"
                  checked={allSelected}
                  ref={selectAllRef}
                  onChange={(e) => onSelectAll?.(e.target.checked)}
                />
              </th>
            )}
            {columns.map((column) => (
              <th
                key={column.key}
                className={clsx('table-cell', `table-align-${column.align || 'left'}`)}
                style={{ width: column.width }}
              >
                <div className="table-header-content">
                  {column.header}
                  {column.sortable && (
                    <span className="table-sort-icon">
                      <svg width="12" height="12" viewBox="0 0 12 12" fill="currentColor">
                        <path d="M6 1L9 4H3L6 1Z" opacity="0.3" />
                        <path d="M6 11L3 8H9L6 11Z" opacity="0.3" />
                      </svg>
                    </span>
                  )}
                </div>
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="table-body">
          {loading ? (
            <tr>
              <td colSpan={columns.length + (hasSelection ? 1 : 0)} className="table-cell table-loading">
                <div className="table-loader">
                  <span className="loader-spinner" />
                  Loading...
                </div>
              </td>
            </tr>
          ) : data.length === 0 ? (
            <tr>
              <td colSpan={columns.length + (hasSelection ? 1 : 0)} className="table-cell table-empty">
                {emptyMessage}
              </td>
            </tr>
          ) : (
            data.map((item, index) => {
              const key = keyExtractor(item);
              const isSelected = hasSelection && selectedSet.has(key);
              const extraRowClass = rowClassName?.(item, index);

              return (
                <tr
                  key={key}
                  className={clsx('table-row', extraRowClass, {
                    'table-row-clickable': onRowClick,
                    'table-row-selected': isSelected,
                  })}
                  onClick={() => onRowClick?.(item)}
                >
                  {hasSelection && (
                    <td className="table-cell table-cell-checkbox">
                      <input
                        type="checkbox"
                        className="checkbox"
                        checked={isSelected}
                        onChange={(e) => {
                          e.stopPropagation();
                          onRowSelect(key, e.target.checked);
                        }}
                      />
                    </td>
                  )}
                  {columns.map((column) => (
                    <td
                      key={column.key}
                      className={clsx('table-cell', `table-align-${column.align || 'left'}`)}
                    >
                      {column.accessor(item)}
                    </td>
                  ))}
                </tr>
              );
            })
          )}
        </tbody>
      </table>
    </div>
  );
}
